#include "threads/fixed-point.h"

/* let x and y be fixed point numbers, and n be an integer */

int
convert_to_fixed_point(int n)
{
    return n * FP_F; 
}

int
convert_to_integer_zero(int x)
{
    return x / FP_F;
}

int
convert_to_integer_nearest(int x)
{
    return x >= 0 ? (x + FP_F / 2) / FP_F : (x - FP_F / 2) / FP_F;
}

int
add_fixed_point(int x, int y)
{
    return x + y;
}

int
sub_fixed_point(int x, int y)
{
    return x - y;
}

int
add_fixed_point_to_integer(int x, int n)
{
    return x + n * FP_F;
}

int
sub_integer_from_fixed_point(int x, int n)
{
    return x - n * FP_F;
}

int
mul_fixed_point(int x, int y)
{
    return ((int64_t) x) * y / FP_F;
}

int
mul_fixed_point_by_integer(int x, int n) 
{
    return x * n;
}

int
div_fixed_point(int x, int y) 
{
    return ((int64_t) x) * FP_F / y;
}

int
div_fixed_point_by_integer(int x, int n)
{
    return x / n;
}
