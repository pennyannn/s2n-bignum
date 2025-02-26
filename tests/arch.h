// On x86 machines, restrict the set of tested functions appropriately
// if the machine does not seem to support the BMI2 and ADX extensions.

enum arch_name { ARCH_X86_64, ARCH_AARCH64 };

#ifdef __x86_64__

int cpuid_extendedfeatures(void)
{ int a = 7, b = 0, c = 0, d = 0;
  asm ("cpuid\n\t"
    : "=a" (a), "=b" (b), "=c" (c), "=d" (d)
    : "0" (a), "2" (c));
  return b;
}

int supports_bmi2_and_adx(void)
{ int c = cpuid_extendedfeatures();
  return (c & (1ul<<8)) && (c & (1ul<<19));
}

int cpuid_aesni(void)
{ int a = 1, b = 0, c = 0, d = 0;
  asm ("cpuid\n\t"
    : "=a" (a), "=b" (b), "=c" (c), "=d" (d)
    : "0" (a), "2" (c));
  return c;
}

// CPUID.01H:ECX.AESNI[bit 25] = 1
int support_aesni(void)
{ int c = cpuid_aesni();
  return (c & (1ul<<25));
}

int cpuid_sse(void)
{ int a = 1, b = 0, c = 0, d = 0;
  asm ("cpuid\n\t"
    : "=a" (a), "=b" (b), "=c" (c), "=d" (d)
    : "0" (a), "2" (c));
  return d;
}

// CPUID.01H:EDX.SSE[bit 25] = 1
// CPUID.01H:EDX.SSE2[bit 26] = 1
int support_sse(void)
{ int d = cpuid_sse();
  return (d & (1ul<<25)) && (d & (1ul<<26));
}

enum arch_name get_arch_name()
{ return ARCH_X86_64;
}

#else

int supports_bmi2_and_adx(void)
{ // AArch64 does not support BMI2 or ADX extension.
  return 0;
}

enum arch_name get_arch_name()
{ return ARCH_AARCH64;
}

#endif

