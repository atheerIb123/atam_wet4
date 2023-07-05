#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <sys/user.h>

#include "elf64.h"

#define	ET_NONE	0	//No file type 
#define	ET_REL	1	//Relocatable file 
#define	ET_EXEC	2	//Executable file 
#define	ET_DYN	3	//Shared object file 
#define	ET_CORE	4	//Core file
#define STB_LOCAL 0
#define SHN_UNDEF 0
#define SHT_SYMTAB 2

/* symbol_name		- The symbol (maybe function) we need to search for.
 * exe_file_name	- The file where we search the symbol in.
 * error_val		- If  1: A global symbol was found, and defined in the given executable.
 * 			- If -1: Symbol not found.
 *			- If -2: Only a local symbol was found.
 * 			- If -3: File is not an executable.
 * 			- If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value		- The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */
Elf64_Addr find_symbol(char* symbol_name, char* exe_file_name, int* error_val) {
    bool symbol_flag = false; // Indicates whether the symbol is found
    FILE* exe_file = fopen(exe_file_name, "rb"); // Open the file in binary mode for read only

    if (exe_file == NULL)
    {
        *error_val = -3; // Couldn't open the file in this case or the file is not an executable
        return 0;
    }
    FILE* file = fopen(exe_file_name, "rb");

    Elf64_Ehdr elf_header;

    size_t elf_header_size = sizeof(Elf64_Ehdr);
    fread(&elf_header, elf_header_size, 1, exe_file); // Read one instance of size = eHdr_size from the file

    if (elf_header.e_type != ET_EXEC)
    {
        *error_val = -3;
        fclose(exe_file);
        return 0;
    }

    // All set to start finding the symbol table

    // Find the symbol table section

    Elf64_Shdr symbol_table_header;
    Elf64_Shdr string_table;
    Elf64_Shdr current;
    Elf64_Shdr dynamicTable;

    size_t sht_size = elf_header.e_shnum * elf_header.e_shentsize;
    fseek(exe_file, elf_header.e_shoff, SEEK_SET);

    uint8_t sht[sht_size];
    fread(sht, elf_header.e_shentsize, elf_header.e_shnum, exe_file);
    size_t Shdr_size = sizeof(current);
    Elf64_Shdr* strtab_sh = NULL;
    Elf64_Shdr* shstrtab_sh = (void *) sht + elf_header.e_shstrndx * elf_header.e_shentsize;

    uint8_t shstrtab[shstrtab_sh->sh_size];
    fseek(exe_file, shstrtab_sh->sh_offset, SEEK_SET);
    fread(shstrtab, 1, sizeof(shstrtab), exe_file);

    for(size_t i = 0; i < elf_header.e_shnum; ++i)
    {
        Elf64_Shdr *sh = (void *) sht + i * elf_header.e_shentsize;

        char* str = shstrtab + sh->sh_name;

        if(strcmp(".strtab", shstrtab + sh->sh_name))
        {
            continue;
        }

        // We found the string table.
        strtab_sh = sh;
        break;
    }

    for (int i = 0; i < elf_header.e_shnum; i++)
    {
        fseek(exe_file, elf_header.e_shoff + i * elf_header.e_shentsize, SEEK_SET);
        fread(&current, Shdr_size, 1, exe_file);
        if (ELF64_R_TYPE(current.sh_type) == SHT_SYMTAB)
        {
            symbol_table_header = current;
        }
        else if(ELF64_R_TYPE(current.sh_type) == 3)
        {
            string_table = current;
        }
    }

    int symbolCount = symbol_table_header.sh_size / sizeof(Elf64_Sym);
    Elf64_Sym sym;
    uint8_t symtab[symbol_table_header.sh_size];
    fseek(exe_file, symbol_table_header.sh_offset, SEEK_SET);
    fread(symtab, symbol_table_header.sh_entsize, symbolCount, exe_file);

    uint8_t strtab[strtab_sh->sh_size];
    fseek(exe_file, strtab_sh->sh_offset, SEEK_SET);
    fread(strtab, 1, sizeof(strtab), exe_file);

    Elf64_Sym* symbol;// = (void *) symtab + i * symbol_table_header.sh_entsize;
    size_t sym_index = 0;

    for(sym_index; sym_index < symbolCount; sym_index++)
    {
        symbol = (void *) symtab + sym_index * symbol_table_header.sh_entsize;
        char* name = strtab + symbol->st_name;

        // If the name is empty skip this symbol.
        if(name == NULL)
            continue;

        if(strcmp(name, symbol_name) == 0)
        {
            symbol_flag = true;
            break;
        }
        else
        {
            symbol_flag = false;
        }
    }

    fclose(exe_file);

    if (!symbol_flag)
    {
        *error_val = -1; // Symbol not found
        return 0;
    }

    if (ELF64_ST_BIND(symbol->st_info) == STB_LOCAL)
    {
        bool flag = false;
        for(size_t i = sym_index + 1; i < symbolCount; i++) {
            symbol = (void *) symtab + i * symbol_table_header.sh_entsize;
            char *name = strtab + symbol->st_name;
            if(strcmp(name, symbol_name) == 0)
            {
                flag = true;
                break;
            }
        }
        if(!flag)
        {
            *error_val = -2; // Symbol is not global
        }
    }

	*error_val=1;
    Elf64_Addr addr = symbol->st_value;

    Elf64_Shdr sh_tab[elf_header.e_shnum];
    fseek(exe_file, elf_header.e_shoff, 0);
    fread(sh_tab, elf_header.e_shnum * elf_header.e_shentsize, 1,exe_file);

	if(symbol->st_shndx == SHN_UNDEF)
    {
		*error_val=-4;
		int num_of_dynamic_symbols;
        Elf64_Off dynamic_sym_offset = dynamicTable.sh_offset;
        Elf64_Xword dynamic_sym_tab_size = dynamicTable.sh_size;
        Elf64_Off dynamic_str_offset;
        Elf64_Xword dynamic_str_tab_size;

        Elf64_Shdr sh_tab[elf_header.e_shnum];
        fseek(file, elf_header.e_shoff, 0);
        fread(sh_tab, elf_header.e_shnum * elf_header.e_shentsize, 1,file);


        for(int i = 0 ; i < elf_header.e_shnum ; i++){
            if(sh_tab[i].sh_type == 11)
            {
                num_of_dynamic_symbols = sh_tab[i].sh_size / sh_tab[i].sh_entsize;
                dynamic_sym_offset = sh_tab[i].sh_offset;
                dynamic_sym_tab_size = sh_tab[i].sh_size;
                dynamic_str_offset = sh_tab[sh_tab[i].sh_link].sh_offset;
                dynamic_str_tab_size = sh_tab[sh_tab[i].sh_link].sh_size;
                break;
            }
        }

        uint8_t strdyntab[dynamic_str_tab_size];
        fseek(file, dynamic_str_offset, SEEK_SET);
        fread(strdyntab, 1, sizeof(strtab), file);

        Elf64_Sym dynamic_sym_tab[num_of_dynamic_symbols];
		fseek(file, dynamic_sym_offset, 0);
		fread(dynamic_sym_tab, dynamic_sym_tab_size, 1, file);

        char dynamic_sym_name[dynamic_str_tab_size];
        fseek(file, dynamic_str_offset, SEEK_SET);
        fread(dynamic_sym_name, dynamic_str_tab_size, 1, file);

		int index=0;
		for(int i = 0 ; i < num_of_dynamic_symbols ; i++){
			if(!strcmp(dynamic_sym_name + dynamic_sym_tab[i].st_name, symbol_name)){
				index=i;
				break;
			}
		}


        int sh_name_size = sh_tab[elf_header.e_shstrndx].sh_size;
		int sh_name_offset = sh_tab[elf_header.e_shstrndx].sh_offset;
		char sh_name[sh_name_size];
		fseek(exe_file, sh_name_offset, 0);

        fread(sh_name, sh_name_size, 1, exe_file);

        int rela_tab_size;
        int rela_tab_offset; 
        int number_of_rela_entries;
        uint8_t shstrtab2[shstrtab_sh->sh_size];

        fseek(file, shstrtab_sh->sh_offset, SEEK_SET);
        fread(shstrtab2, 1, sizeof(shstrtab2), file);


		for(int i = 0; i < elf_header.e_shnum; i++)
        {
            Elf64_Shdr *sh = (void *) sht + i * elf_header.e_shentsize;

			if(!strcmp(shstrtab2 + sh->sh_name, ".rela.plt"))
            {
				rela_tab_size = sh->sh_size;
				rela_tab_offset = sh->sh_offset;
				number_of_rela_entries = sh->sh_size / sh->sh_entsize;
				break;
			}
		}

		Elf64_Rela rela_tab[number_of_rela_entries];
		fseek(file, rela_tab_offset, 0);
		fread(rela_tab, rela_tab_size, 1, file);

		for(int i=0; i < number_of_rela_entries; i++)
        {
			if(ELF64_R_SYM(rela_tab[i].r_info) == index)
            {
				addr = rela_tab[i].r_offset;
				break;
			}
		}
	}

	fclose(exe_file);
    fclose(file);
	return addr;
}

pid_t run_target(const char* file_name, char** args)
{
	pid_t pid = fork();

	if(pid > 0){
		return pid;
	}
	else if(pid == 0)
    {
		if(ptrace(PTRACE_TRACEME, 0 , NULL, NULL) < 0){
			perror("ptrace");
			exit(1);
		}
		execv(file_name, args+2);
	} else{
		perror("fork");
		exit(1);
	}
}

void run_debugger(pid_t child, Elf64_Addr address, bool dynamic){
	int wait_status;
	wait(&wait_status);

	int count = 0;
	struct user_regs_struct regs;
	if(dynamic)
    {
		unsigned long addr = ptrace(PTRACE_PEEKTEXT, child, (void*)address, NULL);
        addr -= 0x6;
		long after_plt = ptrace(PTRACE_PEEKTEXT, child, (void*)(addr), NULL);
		long after_plt_trap = (after_plt & 0xFFFFFFFFFFFFFF00) | 0xCC;
		ptrace(PTRACE_POKETEXT, child, (void*)addr, (void*)after_plt_trap);
		ptrace(PTRACE_CONT, child, NULL, NULL);
		
		wait(&wait_status);



        ptrace(PTRACE_GETREGS, child, 0, &regs);
        unsigned long long returnedVal = regs.rax;
        
        regs.rip-=1;
		ptrace(PTRACE_SETREGS, child, 0 ,&regs);
		ptrace(PTRACE_POKETEXT, child, (void*)addr, (void*)after_plt);

		long trap = regs.rsp;
        unsigned long ret_addr = ptrace(PTRACE_PEEKTEXT, child, (void*)trap, NULL);
		
	
        long after_call = ptrace(PTRACE_PEEKTEXT, child, (void*)ret_addr, NULL);
		long after_call_trap = (after_call & 0xFFFFFFFFFFFFFF00) | 0xCC;

        ptrace(PTRACE_POKETEXT, child, (void*)ret_addr, (void*)after_call_trap);
        ptrace(PTRACE_CONT, child, NULL, NULL);
		
		
		int param = regs.rdi;

        wait(&wait_status);

		ptrace(PTRACE_GETREGS, child, 0, &regs);
		regs.rip -= 1;
		ptrace(PTRACE_SETREGS, child, 0, &regs);
        ptrace(PTRACE_POKETEXT, child, (void*)ret_addr, (void*)after_call);
        count++;
		
		
        int retV = ptrace(PTRACE_PEEKTEXT, child, (void*)(regs.rax), NULL);
        
        retV = regs.rax;
        printf("PRF:: run #%d first parameter is %d\n", count, param);
        printf("PRF:: run #%d returned with %d\n", count, retV);
        address = ptrace(PTRACE_PEEKTEXT, child, (void*)address, NULL);
	}

	unsigned long first_command_in_function = ptrace(PTRACE_PEEKTEXT, child, (void*)address, NULL);
    unsigned long first_command_in_function_trap = (first_command_in_function & 0xFFFFFFFFFFFFFF00) | 0xCC;

    ptrace(PTRACE_POKETEXT, child, (void*)address, (void*)first_command_in_function_trap);
    ptrace(PTRACE_CONT, child, NULL, NULL);
    
    wait(&wait_status);


	while(WIFSTOPPED(wait_status))
    {
		ptrace(PTRACE_GETREGS, child, 0, &regs);
        int param = regs.rdi;
        regs.rip -= 1;
        ptrace(PTRACE_SETREGS, child, 0, &regs);
        ptrace(PTRACE_POKETEXT, child, (void*)address, (void*)first_command_in_function);
        long trap = regs.rsp;
        unsigned long ret_addr = ptrace(PTRACE_PEEKTEXT, child, (void*)trap, NULL);
        long after_call = ptrace(PTRACE_PEEKTEXT, child, (void*)ret_addr, NULL);
        long after_call_trap = (after_call & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, child, (void*)ret_addr, (void*)after_call_trap);
        ptrace(PTRACE_CONT, child, NULL, NULL);
        wait(&wait_status);
        int retV = ptrace(PTRACE_PEEKTEXT, child, (void*)(regs.rax), NULL);
    

        ptrace(PTRACE_GETREGS, child, 0, &regs);
        regs.rip -= 1;
        ptrace(PTRACE_SETREGS, child, 0, &regs);
        ptrace(PTRACE_POKETEXT, child, (void*)ret_addr, (void*)after_call);

        count++;
        printf("PRF:: run #%d first parameter is %d\n", count, param);
        retV = regs.rax;
        
        if(dynamic)
        {
            printf("PRF:: run #%d returned with %d\n", count, retV);

        }
        else
        {
			retV = regs.rax;
            printf("PRF:: run #%d returned with %d\n", count, retV);
        }
        ptrace(PTRACE_POKETEXT, child, (void*)address, (void*)first_command_in_function_trap);
        ptrace(PTRACE_CONT, child, NULL, NULL);
        wait(&wait_status);
        ptrace(PTRACE_GETREGS, child, 0, &regs);
	}
}

int main(int argc, char* argv[])
{
    int err = 0;
	Elf64_Addr addr = find_symbol(argv[1], argv[2], &err);
	bool dynamic = false;
	if (err == -2)
		printf("PRF:: %s is not a global symbol! :(\n", argv[1]);
	else if (err == -1)
		printf("PRF:: %s not found!\n", argv[1]);
	else if (err == -3)
		printf("PRF:: %s not an executable! :(\n", argv[2]);
	else if(err == -4){
		dynamic = true;
	}

    pid_t child_pid = run_target(argv[2], argv);
	run_debugger(child_pid, addr, dynamic);
	return 0;
}
