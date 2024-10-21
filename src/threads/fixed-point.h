#ifndef THREADS_FIXED_POINT_H

#include <stdint.h>

# define FP_P 17
# define FP_Q 14
# define FP_F (1 << FP_P)

#endif

/* let x and y be fixed point numbers, and n be an integer */

int convert_to_fixed_point(int n); 
int convert_to_integer_zero(int x);
int convert_to_integer_nearest(int x);
int add_fixed_point(int x, int y);
int sub_fixed_point(int x, int y);
int add_fixed_point_to_integer(int x, int n);
int sub_integer_from_fixed_point(int x, int n);
int mul_fixed_point(int x, int y);
int mul_fixed_point_by_integer(int x, int n);
int div_fixed_point(int x, int y);
int div_fixed_point_by_integer(int x, int n);
