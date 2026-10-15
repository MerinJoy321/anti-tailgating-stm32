.syntax unified
.thumb
.global tramp
tramp:
    ldr   r0, [sp, #28]
    ldr   r1, [sp, #24]
    orr   r1, r1, #1
    str   r1, [sp, #28]
    msr   APSR_nzcvq, r0
    ldr   r0, [sp, #0]
    ldr   r1, [sp, #4]
    ldr   r2, [sp, #8]
    ldr   r3, [sp, #12]
    ldr   r12, [sp, #16]
    ldr   lr, [sp, #20]
    add   sp, sp, #28
    pop   {pc}
