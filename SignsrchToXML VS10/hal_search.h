// code provided by Andrew based on the work of David Musser and Nishanov
// http://www.team5150.com/~andrew/
// http://www.cs.rpi.edu/~musser/gp/gensearch/index.html

#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <stdint.h>

#define hash_range_max 512
#define suffix_size 2

static int hash(const uint8_t *i) 
{ 
	return ( ((int)i[-1]) + ((int)i[0]) ) & (hash_range_max-1);
}



int search_smallpat( const uint8_t *src, int src_len, const uint8_t *pattern, int pattern_len ) {
	const uint8_t *limit = ( src + src_len - pattern_len ), *p = ( src );

	if ( !src_len || !pattern_len || ( pattern_len > src_len ) )
		return ( -1 );

	for ( ; p <= limit; p++ ) {
		if( !memcmp( p, pattern, pattern_len ) )
			return ( p - src );
	}
	
	return ( -1 );
}

void compute_backtrack_table( const uint8_t *pattern, int pattern_len, int *pattern_backtrack ) {
	int j = ( 0 ), t = ( -1 );
	pattern_backtrack[j] = ( -1 );
	while ( j < pattern_len - 1 ) {
		while ( t >= 0 && pattern[j] != pattern[t] )
			t = ( pattern_backtrack[t] );
		++j; ++t;
		pattern_backtrack[j] = ( pattern[j] == pattern[t] ) ? pattern_backtrack[t] : t;
	}
}

int search_hashed2( const uint8_t *src, int src_len, const uint8_t *pattern, int pattern_len, int *pattern_backtrack ) {
	const uint8_t *src_end = ( src + src_len );
	int skip[ hash_range_max ];
	int k = ( -src_len ), large = ( src_len + 1 ), adjustment = ( large + pattern_len - 1 );
	int i, mismatch_shift;

	if ( src_len <= 0 || pattern_len <= 0 || ( pattern_len > src_len ) )
		return ( -1 );
	if ( pattern_len < suffix_size )
		return ( search_smallpat( src, src_len, pattern, pattern_len ) );

	compute_backtrack_table( pattern, pattern_len, pattern_backtrack );
	for ( i = 0; i < hash_range_max; i++ )
		skip[i] = ( pattern_len - suffix_size + 1 );
	for ( i = 0; i < pattern_len - 1; i++ )
		skip[hash(pattern + i)] = ( pattern_len - 1 - i );
	mismatch_shift = skip[hash(pattern + pattern_len - 1)];
	skip[hash(pattern + pattern_len - 1)] = ( large );

	for (;;) {
		k += ( pattern_len - 1 );
		if ( k >= 0 )
			return ( -1 );
		
		do {
			k += skip[hash(src_end + k)];
		} while ( k < 0 );
		if ( k < pattern_len )
			return ( -1 );
		k -= adjustment;
		
		if ( src_end[k] != pattern[0] ) {
			k += ( mismatch_shift );
			continue;
		}

		for ( i = 1; ; ) {
			if ( src_end[++k] != pattern[i] )
				break;
			if ( ++i == pattern_len )
				return ( ( src_len + k ) - pattern_len + 1 );
		}
		
		if ( mismatch_shift > i ) {
			k += ( mismatch_shift - i );
			continue;
		} 

		for (;;) {
			i = pattern_backtrack[i];
			if ( i <= 0 ) {
				if ( i < 0 )
					k++;
				break;
			}

			while ( src_end[k] == pattern[i] ) {
				k++;
				if ( ++i == pattern_len )
					return ( ( src_len + k ) - pattern_len );
				if ( k == 0 )
					return ( -1 );
			}
		}
	}
}

uint32_t search_hashed( const uint8_t *src, int src_len, const uint8_t *pattern, int pattern_len, int and ) {
	int *pattern_backtrack = (int *)malloc( pattern_len * sizeof( int ) );
	int granularity = ( and >> 3 ), max_and_distance = ( pattern_len * 16 );
	const uint8_t *pattlimit = ( pattern + pattern_len ), *patstart = 0, *p, *start;
	int slicesize = ( granularity ) ? granularity : pattern_len;
	int ofs = -1, remaining = src_len;

	for ( start = src, p = pattern; p < pattlimit; ) {
		ofs = ( search_hashed2( start, remaining, p, slicesize, pattern_backtrack ) );

		if ( ofs != -1 ) {
			remaining -= ( ofs + slicesize );
			if ( !patstart ) {
				patstart = ( start + ofs );
				if ( remaining > max_and_distance )
					remaining = max_and_distance;
			}
			start += ( ofs + slicesize );
			p += slicesize;
		} else {
			if ( !patstart )
				break;
			start = ( patstart + slicesize );
			remaining = ( src_len - ( start - src ) );
			p = ( pattern );
			patstart = ( 0 );
		}
	}

	free( pattern_backtrack );
	return ( ofs != -1 ) ? ( patstart - src ) : (uint32_t)-1;
}
