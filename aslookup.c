#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>

// linked list
struct hLinkedList
{
	char *key;
	char *value;
	struct hLinkedList *next;
};

// hashtable
struct hashTable
{
	int size;
	struct hLinkedList **lists;
};

// build the hash code for the input string
int hashCode(char *str)
{
	int hc;

	hc = 0;
	while ('\0' != *str)
	{
		// for each character, multiply the current hashcode by 31 and add the character's ascii value
		// multiply by 31 is the same as left shift by 5 and subtract value
		hc = hc << 5;
		hc = hc - hc + *str;

		str++;
	}
	return(hc);
}

// create a hashtable - return 0 on failure
int createHashTable(int size, struct hashTable **hashTable)
{
	struct hashTable *ht;
	struct hLinkedList **lists;

	if (size <= 0)
	{
		// bad input
		return(0);
	}

	// create the hashtable
	if (!(ht = (struct hashTable*)malloc(sizeof(struct hashTable))))
	{
		*hashTable = NULL;
		return(0);
	}

	// create the linked lists
	if (!(lists = (struct hLinkedList**)malloc(sizeof(struct hLinkedList *) * size)))
	{
		free(ht);
		*hashTable = NULL;
		return(0);
	}

	ht->size = size;
	ht->lists = lists;

	*hashTable = ht;
	return(1);
}

// destroy a hashtable - return 0 on failure
int destroyHashTable(struct hashTable **ht)
{
	struct hashTable *hashTable;
	struct hLinkedList *list;
	struct hLinkedList *tempList;

	hashTable = *ht;
	if (NULL == hashTable)
	{
		return(1);
	}

	for (int i = 0; i < hashTable->size; i++)
	{
		list = *(hashTable->lists + i);
		while (list)
		{
			// keep track of this list
			tempList = list;

			// advance for looping
			list = list->next;

			// clean
			free(tempList);
		}
	}
	free(hashTable->lists);
	free(hashTable);
	*ht = NULL;
	return(1);
}

// add a string to the hashtable - return 0 on failure
int addToHashTable(struct hashTable *hashTable, char *key, char *value)
{
	int hc;
	int offset;
	struct hLinkedList *list, *prev;

	// create hashcode
	hc = hashCode(key);

	// pick the linked list
	offset = hc % hashTable->size;
	list = *(hashTable->lists + offset);

	if (!list)
	{
		// this list doesn't exist yet - create it
		if (!(list = (struct hLinkedList *)malloc(sizeof(struct hLinkedList))))
		{
			// couldn't get the memory
			return(0);
		}
		*(hashTable->lists + offset) = list;

		list->key = strdup(key);
		list->value = strdup(value);
		list->next = NULL;
		return(1);
	}

	// walk the list
	prev = list;
	while (list)
	{
		if (0 == strcmp(list->key, key))
		{
			// already exists in the list - update the value
			if (strcmp(value, "unknown") != 0) // special handling for unknown prefix.
				list->value = strdup(value); // only overwrite if a known prefix is found.
			return(1);
		}

		prev = list;
		list = list->next;
	}

	// string doesn't yet exist in hashtable - add it. prev is at the end
	if (!(list = (struct hLinkedList *)malloc(sizeof(struct hLinkedList))))
	{
		// couldn't get the memory
		return(0);
	}
	list->key = strdup(key);
	list->value = strdup(value);
	list->next = NULL;
	prev->next = list;

	return(1);
}

static void bytes_to_bitmap(int byte, char *bitmap) {
	int offset = 0;
	//assert(byte >= 0); assert(byte <= 255);

	for (int i = 7; i >= 0; i--) {
		if ((byte & (1 << i)) != 0) {
			bitmap[offset++] = '1';
		}
		else {
			bitmap[offset++] = '0';
		}
	}
}

static int addr_matches_prefix(char *addr, char *prefix) {
	// Check if an IP prefix covers an IP address. The addr field is an IPv4 // address in textual form (e.g., "130.209.240.1"); the prefix field has
	// its prefix length specified in the usual address/length format (e.g., // "130.209.0.0/16"). Return 1 if the prefix covers the address, or zero
	// otherwise. This is not an efficient implementation, but is simple to // debug, since the bitmaps it uses for comparison are printable text.
	// Parse the address: 
	int addr_bytes[4];
	char addr_bitmap[32 + 1];
	sprintf(addr_bitmap, " ");
	if (sscanf(addr, "%d.%d.%d.%d", &addr_bytes[0], &addr_bytes[1], &addr_bytes[2], &addr_bytes[3]) != 4) { printf("cannot parse addr\n"); return 0; }
	for (int i = 0; i < 4; i++) { bytes_to_bitmap(addr_bytes[i], &addr_bitmap[i * 8]); }
	// Parse the prefix: 
	int prefix_bytes[4]; int prefix_len; char prefix_bitmap[32 + 1];
	sprintf(prefix_bitmap, " ");
	if (sscanf(prefix, "%d.%d.%d.%d/%d", &prefix_bytes[0], &prefix_bytes[1], &prefix_bytes[2], &prefix_bytes[3], &prefix_len) != 5) { printf("cannot parse prefix\n"); return 0; }
	for (int i = 0; i < 4; i++) { bytes_to_bitmap(prefix_bytes[i], &prefix_bitmap[i * 8]); }

	for (int i = prefix_len + 1; i < 33; i++) { prefix_bitmap[i - 1] = '?'; }
	// Check if address matches prefix: 
	for (int i = 0; i < 32; i++) { if ((addr_bitmap[i] != prefix_bitmap[i]) && (prefix_bitmap[i] != '?')) { return 0; } } return 1;
}

static void printKnownAS(struct hashTable *hashtable) {
	FILE *inf = fopen("autnums.html", "r");

	if (inf != NULL) {
		int buflen = 1024;
		char buffer[buflen + 1];
		while (!feof(inf)) {
			memset(buffer, 0, buflen + 1);
			fgets(buffer, buflen, inf);
			if (strncmp(buffer, "<a href=\"/cgi-bin/as-report=AS", 8) == 0) {
				int asnum;
				char asname[1024];
				char *p = "<a href=\"/cgi-bin/as-report?as=AS%d&view=2.0\">AS%d </a> %[^\n]s";
				if (sscanf(buffer, p, &asnum, &asnum, asname) == 3) {

					struct hLinkedList *list;

					for (int i = 0; i < hashtable->size; i++)
					{
						list = *(hashtable->lists + i);
						while (list)
						{
							if (atoi(list->value) == asnum && strcmp(list->value, "unknown") != 0) {
								printf("\n%s %d %s", list->key, asnum, asname);
							}
							list = list->next;
						}
					}
				}
			}
		}
		fclose(inf);
	}
}

static void printUnknown(struct hashTable *hashtable) {
	struct hLinkedList *anotherlist;

	for (int i = 0; i < hashtable->size; i++)
	{
		anotherlist = *(hashtable->lists + i);
		while (anotherlist)
		{
			if (strcmp(anotherlist->value, "unknown") == 0) {
				printf("\n%s %s %s\n", anotherlist->key, "-", anotherlist->value);
			}

			anotherlist = anotherlist->next;
		}
	}
}

int main(int argc, char *argv[]) {
	char str[512];
	char *token;

	char *asValue;
	char prefix1[512];
	char prefix2[512];
	char asNum[512];
	struct hashTable *ht;
	int size = 256;
	int count = 0;

	createHashTable(size, &ht);

	char filename[100] = "bgpdump -Mv ";
	strcat(filename, argv[1]);

	FILE *rib_file = popen(filename, "r");

	if (rib_file) {
		while (fgets(str, sizeof str, rib_file) != NULL) {

			token = strtok(str, "|"); // string tokeniser to split the entire line from rib file.

			if (token != NULL) {

				for (int i = 0; i < 5; i++) { // loop until the position we want to get the required prefix and AS number.
					token = strtok(NULL, "|");

					if (token != NULL) {
						if (i == 4) { // reached position for prefix

							if (strcmp(prefix2, token) != 0) { // check if token is NOT the same as previously processed prefix.

								strcpy(prefix1, token); // current prefix to be processed.
								strcpy(prefix2, token); // temp prefix to save previous.

								token = strtok(NULL, "|"); //  getting the AS numbers from next position.
								strcpy(asNum, token);

								asValue = strrchr(asNum, ' '); // get the value of the destination AS.
								token = strtok(NULL, "|");

								if (asValue != NULL) {
									for (int j = 2; j < argc; j++) { // loop through all arguments starting from the first IP address
										char *argsaddr = (char*)malloc(sizeof(argv[j])); // to save the argument ip address
										char *prefix = (char*)malloc(sizeof(prefix1)); // to save the first prefix
										strcpy(argsaddr, argv[j]);
										strcpy(prefix, prefix1);

										char *add = (char*)malloc(sizeof(argv[j])); // duplicate to get first "number" from ip address
										char *pre = (char*)malloc(sizeof(prefix1)); // duplicate to get first "number" from prefix
										strcpy(add, argv[j]);
										strcpy(pre, prefix1);

										char *addfirst = strtok(add, "."); // tokeniser to get first number
										char *prefirst = strtok(pre, "."); // tokeniser to get first number

										if (strcmp(addfirst, prefirst) == 0 && addr_matches_prefix(argsaddr, prefix) == 1) { // checking if the address matches a prefix
											char *key = (char*)malloc(sizeof(argsaddr)); // to save the key (ip address from arguments) to hashtable
											char *value = (char*)malloc(sizeof(asValue)); // to save the value (AS number) to hashtable
											strcpy(key, argsaddr);
											strcpy(value, asValue);
											addToHashTable(ht, key, value); // add to hashtable
										}
										if (strcmp(addfirst, prefirst) == 0 && addr_matches_prefix(argsaddr, prefix) == 0) { // checking if the address does NOT match a prefix
											char *key = (char*)malloc(sizeof(argsaddr)); // to save the key (ip address from arguments) to hashtable
											char *value = (char*)malloc(sizeof(asValue)); // to save the value (AS number) to hashtable
											strcpy(key, argsaddr);
											strcpy(value, "unknown"); // set AS number value to unknown
											addToHashTable(ht, key, value); // add to hashtable
										}
									}
								} // end if asValue != NULL
								break;
							} // end if
							else { // when token is the same as previous prefix
								break;
							}
						} // end if (token = 4)
					} // end if (token != NULL)
					else {
						break; // stop if token is null
					}
				}//end for loop
			}//end of if

			count++;

			if (count == 100000) {
				printf(".");
				fflush(stdout);
				count = 0;
			}
		}//end of while
		fclose(rib_file);
	}//end of if

	printKnownAS(ht);
	printUnknown(ht);

	destroyHashTable(&ht);
	return 0;
}



