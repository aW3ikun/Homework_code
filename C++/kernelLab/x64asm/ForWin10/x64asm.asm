;¥Û–°–¥√Ù∏–
option casemap:none

extern	 x:qword	
;main Proto

.data
;ttt qword ?
.code

IdtEntry Proc
	;mov rax, cr3
	;mov x,rax
	mov     rsp, gs:7000h
	mov     cr3, rsp
	
	mov     rsp, gs:7008h
	mov     gs:10h, rsi
	mov     rsi, gs:38h
	add     rsi, 4200h
	push    qword ptr [rsi-8]
	push    qword ptr [rsi-10h]
	push    qword ptr [rsi-18h]
	push    qword ptr [rsi-20h]
	push    qword ptr [rsi-28h]
	mov     rsi, gs:10h
	and     qword ptr gs:10h, 0


	iretq
IdtEntry Endp

go	PROC
	int 21h
	ret
go ENDP	

END