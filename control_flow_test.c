//Simple static test case for decompilation

int main (void)
{
	int a, b, c, d, e;
	a = 1;
	b = 10;
label:
	c = 11;
	d = 0;

	while (a > 0)
	{
		a --;
		if (b)
			break;
		b ++;
	}

	do
	{
		b --;
		if (c)
			continue;
		c --;
	} while (b >= a);

	if (b)
	{
		if (a)
			c = 1;
		else
			c = 2;
	}
	else
	{
		if (!d)
			c = 6;
	}

	a = 0;
	if (a)
		a = 2;
	else
		a = 3;

	while (a < 10)
		a ++;
	a = 11;
	if (c == b)
		goto label;
	c = 10;
	b = c;

	return c;
}
