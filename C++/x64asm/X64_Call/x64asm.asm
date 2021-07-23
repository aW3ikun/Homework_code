;¥Û–°–¥√Ù∏–
option casemap:none

;main Proto

func Proto
printf Proto
.data
;ttt qword ?
pStr DB 'this is in asm_func',0Ah,00h
.code

asm_func Proc
	push rdi
	sub rsp,30h
	lea rcx,[pStr]
	call printf	
	;add rsp,20h
	
	mov rdi,1
	mov rcx,rdi
	mov rcx,1
	mov rdx,2
	mov r8,3
	mov r9,4

	;sub rsp,28h
	mov qword ptr [rsp+20h],5

	call func
	;add rsp,28h
	lea rsp,qword ptr [rsp+30h]
	pop rdi
	ret
asm_func Endp

END