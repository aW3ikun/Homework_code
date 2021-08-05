;大小写敏感
option casemap:none

extern	 x:qword	
;main Proto

.data
;ttt qword ?
.code

IdtEntry Proc
	mov rax, [0FFFFF8034C6AF010h]
	stac ; 开启AC=关闭SMAP
	mov x,rax
	iretq
IdtEntry Endp

go	PROC
	int 21h
	ret
go ENDP	

END