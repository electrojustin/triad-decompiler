//Simple static test case for decompilation

int func1 (int a, int b);
int func2 (int a, int b);
int func3 (int a, int b);

int main (void)
{
	int a, b, c, d, e;
	a = 2;
	b = 3;
	c = func1 (a, b); //Make some random function calls
	d = func2 (a, b);
	e = func3 (a, b);
	return c+d+e;
	return 0;
}

int func1 (int a, int b) //Silly arithmetic
{
	return a+b;
}

int func2 (int a, int b)
{
	return b-a;
}

int func3 (int a, int b)
{
	return a*b;
}
