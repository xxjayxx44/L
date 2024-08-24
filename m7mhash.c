#include "cpuminer-config.h"
#include "miner.h"

#include <gmp.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <float.h>
#include <math.h>
#include <sph_sha2.h>
#include <sph_keccak.h>
#include <sph_haval.h>
#include <sph_tiger.h>
#include <sph_whirlpool.h>
#include <sph_ripemd.h>

#define EPSa DBL_EPSILON
#define EPS1 DBL_EPSILON
#define EPS2 3.0e-11

inline double exp_n(double xt) {
    if(xt < -700.0) return 0;
    else if(xt > 700.0) return 1e200;
    else if(xt > -0.8e-8 && xt < 0.8e-8) return (1.0 + xt);
    else return exp(xt);
}

inline double exp_n2(double x1, double x2) {
    double p1 = -700., p2 = -37., p3 = -0.8e-8, p4 = 0.8e-8, p5 = 37., p6 = 700.;
    double xt = x1 - x2;
    if (xt < p1+1.e-200) return 1.;
    else if (xt > p1 && xt < p2 + 1.e-200) return ( 1. - exp(xt) );
    else if (xt > p2 && xt < p3 + 1.e-200) return ( 1. / (1. + exp(xt)) );
    else if (xt > p3 && xt < p4) return ( 1. / (2. + xt) );
    else if (xt > p4 - 1.e-200 && xt < p5) return ( exp(-xt) / (1. + exp(-xt)) );
    else if (xt > p5 - 1.e-200 && xt < p6) return ( exp(-xt) );
    else if (xt > p6 - 1.e-200) return 0.;
}

double swit2_(double wvnmb) {
    return pow( (5.55243*(exp_n(-0.3*wvnmb/15.762) - exp_n(-0.6*wvnmb/15.762)))*wvnmb, 0.5) 
	  / 1034.66 * pow(sin(wvnmb/65.), 2.);
}
