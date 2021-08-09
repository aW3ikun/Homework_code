;大小写敏感
option casemap:none

extern	 x:qword	
;main Proto

.data
;ttt qword ?
.code

IdtEntry Proc

	swapgs	
	mov     gs:[7010h], rsp
	mov     rsp, gs:[7000h]
	bt      dword ptr gs:[7018h], 1
	jb      short @AA
	mov     cr3, rsp
@AA:
	 mov     rsp, gs:[7008h]; 获取rsp
	 mov      gs:[10h], rsi
	 mov     rsi, gs:[38h]
	 add     rsi, 4200h      ; idtbase+4200h处保存中断前的信息
	 push    qword ptr [rsi-8] ; ss
	 push    qword ptr [rsi-10h] ; rsp
	 push    qword ptr [rsi-18h] ; rflags
	 push    qword ptr [rsi-20h] ; cs
	 push    qword ptr [rsi-28h] ; rip
	 mov     rsi, gs:[10h]
	 and     qword ptr gs:[10h], 0 
	sti

@L:
	jmp @L

	iretq
IdtEntry Endp

go	PROC
	int 21h
	ret
go ENDP	

END