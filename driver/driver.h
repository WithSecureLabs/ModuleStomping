#pragma once

struct privateInfo
{
	PDEVICE_OBJECT deviceObject;
	unsigned long long PFNDatabase;
}; typedef struct privateInfo privateInfo;

extern privateInfo prv;

