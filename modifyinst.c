#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <elf.h>
#include "inst.h"
#include "cpu.h"

#define roundup(x, y) ((((x) + ((y) - 1)) / (y)) * (y))

unsigned int inst_count = 0;
unsigned int modified_inst_count = 0;

void modifyInstruction(Instruction *iHead, Sectionlist *sectionList, int sectionnum)
{
	Instruction *iOriginal;
	Instruction *iCurrent;
	Instruction *iTemp;

	extern int stringtablesize;
	extern char* stringtable;

	Symbollist *sTail;
	Symbollist *sTemp;

	Relocationlist *rTail;
	Relocationlist *rTemp;

	int i;
	int instsize;
	int functionname;

	// add detecting function name to string table
	/*
	functionname = stringtablesize;
	stringtable = (char *)realloc(stringtable, sizeof(char) * (stringtablesize + strlen("__detect_abnormal__")));
	memcpy(stringtable + stringtablesize, "__detect_abnormal__", strlen("__detect_abnormal__"));
	stringtablesize += strlen("__detect_abnormal__");
	stringtable[stringtablesize] = '\0';

	// find symbol table
	for(i=0; sectionList[i].sectionindex != -1; i++)
	{
		if(sectionList[i].sectionHeader.sh_type == SHT_SYMTAB)
		{
			sTail = sectionList[i].symbolhead;
			if(sTail == NULL)
				break;
			while(sTail->next != NULL)
				sTail = sTail->next;

			sTemp = (Symbollist*)malloc(sizeof(*sTemp));
			sTemp->symbolindex = sTail->symbolindex+1;
			sTemp->symbolinfo.st_name = functionname;
			sTemp->symbolinfo.st_value = 0;
			sTemp->symbolinfo.st_size = 0;
			sTemp->symbolinfo.st_info = ((STB_GLOBAL) << 4) + ((STT_FUNC) & 0xF);
			sTemp->symbolinfo.st_other = 0;
			sTemp->symbolinfo.st_shndx = SHN_UNDEF;

			sTemp->prev = sTail;
			sTemp->next = NULL;
			sTail->next = sTemp;
			sTail = sTemp;
		}
	}
	// find relocation table
	rTail = NULL;
	for(i = 0; sectionList[i].sectionindex != -1; i++)
	{
		if(sectionList[i].sectionHeader.sh_type == SHT_REL && sectionList[i].sectionHeader.sh_info == sectionnum)
		{
			rTail = sectionList[i].relocationhead;

			if(rTail == NULL)
				break;
			while(rTail->next != NULL)
				rTail = rTail->next;
		}
	}
*/
	if(iHead == NULL)
		return;

	iCurrent = iHead->next;
	while(iCurrent != NULL)
	{
		inst_count++;
		if(iCurrent->instruction_type == INSTTYPE_NORMAL)
		{
			modified_inst_count++;
			iCurrent->isAdded = 1;
			iCurrent->blockSize =	iCurrent->prefix_size +
						iCurrent->opcode_size +
						iCurrent->modrm_size +
						iCurrent->sib_size +
						iCurrent->displacement_size +
						iCurrent->immediate_size;

			iOriginal = iCurrent;
			/*
			iTemp = create_inst(NULL, NULL, iCurrent);
			if(iTemp!=NULL)
			{
				iTemp->prev = iCurrent;
				iTemp->next = iCurrent->next;
				iCurrent->next = iTemp;
				iCurrent = iTemp;
			}
			*/
			/* push, mov, mov, pop sequence
			// push %eax
			iTemp = (Instruction *)malloc(sizeof(Instruction));
			iTemp = (Instruction *)malloc(sizeof(*iTemp));
			memset(iTemp, 0, sizeof(*iTemp));
			iTemp->section_index = sectionnum;
			iTemp->absolute_address = 0;
			iTemp->offset = 0;
			iTemp->instruction_type = INSTTYPE_NORMAL;
			iTemp->instruction_code = INSTCODE_PUSH;
			iTemp->prefix_size = 0;
			iTemp->opcode_size = 1;
			iTemp->opcode[0] = 0x50;
			iTemp->modrm_size = 0;
			iTemp->displacement_size = 0;
			iTemp->immediate_size = 0;
			iTemp->instruction_size = 1;
			iTemp->prev = iCurrent;
			iTemp->next = iCurrent->next;
			iCurrent->next = iTemp;
			iCurrent = iTemp;

			// mov %eax, (%esp)
			iTemp = (Instruction *)malloc(sizeof(Instruction));
			iTemp = (Instruction *)malloc(sizeof(*iTemp));
			memset(iTemp, 0, sizeof(*iTemp));
			iTemp->section_index = sectionnum;
			iTemp->absolute_address = 0;
			iTemp->offset = 0;
			iTemp->instruction_type = INSTTYPE_NORMAL;
			iTemp->instruction_code = INSTCODE_MOV;
			iTemp->prefix_size = 0;
			iTemp->opcode_size = 1;
			iTemp->opcode[0] = 0x89;
			iTemp->modrm_size = 1;
			iTemp->modrm = 0x04;
			iTemp->sib_size = 1;
			iTemp->sib = 0x24;
			iTemp->displacement_size = 0;
			iTemp->immediate_size = 0;
			iTemp->instruction_size = 3;
			iTemp->prev = iCurrent;
			iTemp->next = iCurrent->next;
			iCurrent->next = iTemp;
			iCurrent = iTemp;

			// mov (%esp), %eax
			iTemp = (Instruction *)malloc(sizeof(Instruction));
			iTemp = (Instruction *)malloc(sizeof(*iTemp));
			memset(iTemp, 0, sizeof(*iTemp));
			iTemp->section_index = sectionnum;
			iTemp->absolute_address = 0;
			iTemp->offset = 0;
			iTemp->instruction_type = INSTTYPE_NORMAL;
			iTemp->instruction_code = INSTCODE_MOV;
			iTemp->prefix_size = 0;
			iTemp->opcode_size = 1;
			iTemp->opcode[0] = 0x8B;
			iTemp->modrm_size = 1;
			iTemp->modrm = 0x04;
			iTemp->sib_size = 1;
			iTemp->sib = 0x24;
			iTemp->displacement_size = 0;
			iTemp->immediate_size = 0;
			iTemp->instruction_size = 3;
			iTemp->prev = iCurrent;
			iTemp->next = iCurrent->next;
			iCurrent->next = iTemp;
			iCurrent = iTemp;

			// pop %eax
			iTemp = (Instruction *)malloc(sizeof(Instruction));
			iTemp = (Instruction *)malloc(sizeof(*iTemp));
			memset(iTemp, 0, sizeof(*iTemp));
			iTemp->section_index = sectionnum;
			iTemp->absolute_address = 0;
			iTemp->offset = 0;
			iTemp->instruction_type = INSTTYPE_NORMAL;
			iTemp->instruction_code = INSTCODE_PUSH;
			iTemp->prefix_size = 0;
			iTemp->opcode_size = 1;
			iTemp->opcode[0] = 0x58;
			iTemp->modrm_size = 0;
			iTemp->displacement_size = 0;
			iTemp->immediate_size = 0;
			iTemp->instruction_size = 1;
			iTemp->prev = iCurrent;
			iTemp->next = iCurrent->next;
			iCurrent->next = iTemp;
			iCurrent = iTemp;
			*/
			///*	nop test
			//for(i=0, instsize = iCurrent->instruction_size * 2; i<instsize; i++)
			//for(i=0, instsize = iCurrent->instruction_size; i<instsize; i++)
			for(i=0; i<2; i++)
			{
				iTemp = (Instruction *)malloc(sizeof(Instruction));
				iTemp = (Instruction *)malloc(sizeof(*iTemp));
				memset(iTemp, 0, sizeof(*iTemp));
				iTemp->isAdded = 2;
				iTemp->section_index = sectionnum;
				iTemp->absolute_address = 0;
				iTemp->offset = 0;
				iTemp->instruction_type = INSTTYPE_NORMAL;
				iTemp->instruction_code = INSTCODE_NOP;
				iTemp->prefix_size = 0;
				iTemp->opcode_size = 2;
				iTemp->opcode[0] = 0x0F;
				iTemp->opcode[1] = 0x1F;
				iTemp->modrm_size = 1;
				iTemp->modrm = 0x00;
				iTemp->sib_size = 0;
				iTemp->displacement_size = 0;
				iTemp->immediate_size = 0;
				iTemp->instruction_size = 3;
				if(iCurrent->next != NULL)
					iCurrent->next->prev=iTemp;
				iTemp->prev = iCurrent;
				iTemp->next = iCurrent->next;
				iCurrent->next = iTemp;
				iCurrent = iTemp;
				iOriginal->blockSize += iTemp->instruction_size;
			}
			//*/
		}
		else
		{
			switch(iCurrent->opcode[0])
			{
				case 0xEB:	// jmp relavite displacement(1)
					iCurrent->opcode[0] = 0xE9;
					iCurrent->displacement_size = 4;
					iCurrent->instruction_size =	iCurrent->prefix_size +
													iCurrent->opcode_size +
													iCurrent->modrm_size +
													iCurrent->sib_size +
													iCurrent->displacement_size +
													iCurrent->immediate_size;
					break;

				case 0x77:	// JA
				case 0x73:	// JAE
				case 0x72:	// JB, JC
				case 0x76:	// JBE
				case 0x74:	// JE
				case 0x7F:	// JG
				case 0x7D:	// JGE
				case 0x7C:	// JL
				case 0x7E:	// JLE
				case 0x75:	// JNE
				case 0x71:	// JNO
				case 0x7B:	// JNP
				case 0x79:	// JGE
				case 0x70:	// JO
				case 0x7A:	// JP
				case 0x78:	// JPO
					iCurrent->opcode[1] = iCurrent->opcode[0] + 0x10;
					iCurrent->opcode[0] = 0x0F;
					iCurrent->opcode_size = 2;
					iCurrent->displacement_size = 4;
					iCurrent->instruction_size =	iCurrent->prefix_size +
													iCurrent->opcode_size +
													iCurrent->modrm_size +
													iCurrent->sib_size +
													iCurrent->displacement_size +
													iCurrent->immediate_size;
					break;

					/*
				case 0xC9:	// LEAVE
					iTemp = (Instruction *)malloc(sizeof(*iTemp));
					memset(iTemp, 0, sizeof(*iTemp));
					iTemp->section_index = sectionnum;
					iTemp->absolute_address = 0;
					iTemp->offset = 0;
					iTemp->instruction_type = INSTTYPE_CALL;
					iTemp->instruction_code = INSTCODE_CALL;
					iTemp->prefix_size = 0;
					iTemp->opcode_size = 1;
					iTemp->opcode[0] = 0xE8;
					iTemp->modrm_size = 0;
					iTemp->sib_size = 0;
					iTemp->displacement_size = 4;
					iTemp->displacement[0] = 0xFC;
					iTemp->displacement[1] = 0xFF;
					iTemp->displacement[2] = 0xFF;
					iTemp->displacement[3] = 0xFF;
					iTemp->immediate_size = 0;
					iTemp->instruction_size = 0;
					iTemp->prev = iCurrent->prev;
					iTemp->next = iCurrent;

					if(iCurrent->prev != NULL)
						iCurrent->prev->next = iTemp;

					iCurrent->prev = iTemp;
					rTemp = (Relocationlist *)malloc(sizeof(*rTemp));
					memset(rTemp, 0, sizeof(*rTemp));
					rTemp->modifying_instruction = iTemp;
					rTemp->offset_in_instruction = 1;
					rTemp->relocationinfo.r_info = ((sTemp->symbolindex) << 8) + (unsigned char)(R_386_PC32);
					rTemp->prev = rTail;
					rTemp->next = NULL;
					rTail->next = rTemp;
					rTail = rTemp;
					break;
			*/
				default:
					break;
			}
		}
		iCurrent = iCurrent->next;
	}
}

unsigned long adjustInstructionlist(Instruction *iHead, Sectionlist *sectionlist, int sectionnumber)
{
	Instruction *iCurrent;
	unsigned long offset;

	if(iHead == NULL)
		return;

	iCurrent = iHead->next;

	offset = 0;

	while(iCurrent != NULL)
	{
		iCurrent->offset = offset;
		iCurrent->instruction_size = 	iCurrent->prefix_size +
										iCurrent->opcode_size +
										iCurrent->modrm_size +
										iCurrent->sib_size +
										iCurrent->displacement_size +
										iCurrent->immediate_size;
		offset += iCurrent->instruction_size;
		iCurrent = iCurrent->next;
	}
	return offset;
}

void alignInstructionList(Instruction *iHead, Sectionlist *sectionList, int sectionnumber, int alignFactor)
{
	if(alignFactor==0)
		return;
	Instruction *iCurrent;
	unsigned long prev_offset = 0;
	unsigned long offset = 0;
	unsigned long address;
	unsigned long blockStart;
	unsigned long blockEnd;
	unsigned long base;

	Instruction *originalHead;
	Instruction *modifyHead;
	Instruction *iTemp;

	unsigned short state = 0;

	int insttype;

	int size;
	int i;

	iCurrent = iHead;

	base = sectionList[sectionnumber].sectionHeader.sh_addr;
	base = roundup(base, 2<<(alignFactor-1));
	sectionList[sectionnumber].sectionHeader.sh_addr = base;
	sectionList[sectionnumber].sectionHeader.sh_addralign = 2<<(alignFactor-1);
//	blockStart = base;
	blockStart = 0;
	blockEnd = blockStart + (2<<(alignFactor-1)) - 1;

	if(iHead == NULL)
		return;

	iCurrent = iHead->next;
	while(iCurrent!=NULL)
	{
		while(offset > blockEnd)
		{
			blockStart = blockEnd+1;
			blockEnd = blockStart + (2<<(alignFactor-1)) - 1;
		}

		address = base + iCurrent->offset;
		insttype = iCurrent->instruction_type;

		if(	(offset != blockStart)&&
			(insttype == INSTTYPE_JMP	|| insttype == INSTTYPE_CALL	||
			insttype == INSTTYPE_JCC	|| insttype == INSTTYPE_BRANCH	||
			insttype == INSTTYPE_RET))
		{
			size = blockEnd - offset;

			for(i=0; i<=size; i++)
			{
				iTemp = (Instruction *)malloc(sizeof(Instruction));
				iTemp = (Instruction *)malloc(sizeof(*iTemp));
				memset(iTemp, 0, sizeof(*iTemp));
				iTemp->isAdded = 1;
				iTemp->section_index = sectionnumber;
				iTemp->absolute_address = 0;
				iTemp->offset = 0;
				iTemp->instruction_type = INSTTYPE_NORMAL;
				iTemp->instruction_code = INSTCODE_NOP;
				iTemp->prefix_size = 0;
				iTemp->opcode_size = 1;
				iTemp->opcode[0] = 0x90;
				iTemp->modrm_size = 0;
				iTemp->sib_size = 0;
				iTemp->displacement_size = 0;
				iTemp->immediate_size = 0;
				iTemp->instruction_size = 1;
				iCurrent->prev->next=iTemp;
				iTemp->prev = iCurrent->prev;
				iTemp->next = iCurrent;
				offset++;
				iCurrent->prev = iTemp;
			}
			offset += iCurrent->instruction_size;
			iCurrent = iCurrent->next;
		}
		else if( 	iCurrent->isAdded == 1 &&
				iCurrent->blockSize > iCurrent->instruction_size && 
				(offset + iCurrent->blockSize) > (blockEnd-2))
		{
			//printf("There?\n");
			size = blockEnd - offset;

			for(i=0; i<=size; i++)
			{
				iTemp = (Instruction *)malloc(sizeof(Instruction));
				iTemp = (Instruction *)malloc(sizeof(*iTemp));
				memset(iTemp, 0, sizeof(*iTemp));
				iTemp->isAdded = 1;
				iTemp->section_index = sectionnumber;
				iTemp->absolute_address = 0;
				iTemp->offset = 0;
				iTemp->instruction_type = INSTTYPE_NORMAL;
				iTemp->instruction_code = INSTCODE_NOP;
				iTemp->prefix_size = 0;
				iTemp->opcode_size = 1;
				iTemp->opcode[0] = 0x90;
				iTemp->modrm_size = 0;
				iTemp->sib_size = 0;
				iTemp->displacement_size = 0;
				iTemp->immediate_size = 0;
				iTemp->instruction_size = 1;
				iCurrent->prev->next=iTemp;
				iTemp->prev = iCurrent->prev;
				iTemp->next = iCurrent;
				offset++;
				iCurrent->prev = iTemp;
			}
			offset += iCurrent->instruction_size;
			iCurrent = iCurrent->next;
		}
		else if(	iCurrent->isAdded == 0 && blockEnd - offset <= 2)
		{
			size = blockEnd - offset;

			for(i=0; i<=size; i++)
			{
				iTemp = (Instruction *)malloc(sizeof(Instruction));
				iTemp = (Instruction *)malloc(sizeof(*iTemp));
				memset(iTemp, 0, sizeof(*iTemp));
				iTemp->isAdded = 1;
				iTemp->section_index = sectionnumber;
				iTemp->absolute_address = 0;
				iTemp->offset = 0;
				iTemp->instruction_type = INSTTYPE_NORMAL;
				iTemp->instruction_code = INSTCODE_NOP;
				iTemp->prefix_size = 0;
				iTemp->opcode_size = 1;
				iTemp->opcode[0] = 0x90;
				iTemp->modrm_size = 0;
				iTemp->sib_size = 0;
				iTemp->displacement_size = 0;
				iTemp->immediate_size = 0;
				iTemp->instruction_size = 1;
				iCurrent->prev->next=iTemp;
				iTemp->prev = iCurrent->prev;
				iTemp->next = iCurrent;
				offset++;
				iCurrent->prev = iTemp;
			}
		}
		else if(	iCurrent->isAdded == 0 && blockEnd - offset - iCurrent->instruction_size < 2)
		{
			//printf("Here?\n");
			size = blockEnd - offset;

			for(i=0; i<=size; i++)
			{
				iTemp = (Instruction *)malloc(sizeof(Instruction));
				//iTemp = (Instruction *)malloc(sizeof(*iTemp));
				if(iTemp == NULL)
				{
					printf("Not enough heap\n");
					exit(0);
				}
				memset(iTemp, 0, sizeof(Instruction));
				iTemp->isAdded = 1;
				iTemp->section_index = sectionnumber;
				iTemp->absolute_address = 0;
				iTemp->offset = 0;
				iTemp->instruction_type = INSTTYPE_NORMAL;
				iTemp->instruction_code = INSTCODE_NOP;
				iTemp->prefix_size = 0;
				iTemp->opcode_size = 1;
				iTemp->opcode[0] = 0x90;
				iTemp->modrm_size = 0;
				iTemp->sib_size = 0;
				iTemp->displacement_size = 0;
				iTemp->immediate_size = 0;
				iTemp->instruction_size = 1;
				iCurrent->prev->next=iTemp;
				iTemp->prev = iCurrent->prev;
				iTemp->next = iCurrent;
				offset++;
				iCurrent->prev = iTemp;
			}
		}
		else
		{
			offset += iCurrent->instruction_size;
			iCurrent = iCurrent->next;
		}
	}
}
