#ifndef __DELEGATOR_CLIENT_H__
#define __DELEGATOR_CLIENT_H__

#include <bundle.h>

int delegator_client_launch(const char *zone, bundle *kb);
int delegator_client_can_jump(char **zone, bundle *kb);

#endif	/* __DELEGATOR_CLIENT_H__ */

