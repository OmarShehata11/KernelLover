#include "DriverHeader.h"

PHV_VIRTUAL_MACHINE_STATE GuestVmState;

int HvMathPower(int base, int exp)
{
	int result = 1;

	for (;;)
	{
		if (exp & 1)
		{
			result *= base;
		}

		exp >>= 1;
		if (!exp)
		{
			break;
		}
		base *= base;
	}

	return result;
}
