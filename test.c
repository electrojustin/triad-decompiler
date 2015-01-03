//Simple static test case for decompilation

int main (void)
{
	int a = 1;
	int b;

	switch (a)
	{
		case 1:
			b = 2;
		case 2:
			b = 1;
		case 3:
			b = -6;
		case 4:
			b = -7;
		default:
			b = 1024;
	}
}
