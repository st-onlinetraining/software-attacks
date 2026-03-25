#include <stdio.h>
#include <string.h>
#include "slot.h"

#define ACCESS_NO 0
#define ACCESS_R 1 /* authorization to read */
#define ACCESS_W 2 /* authorization to write */
#define ACCESS_RW (ACCESS_R|ACCESS_W)
#define ACCESS_I 4 /* authorization to increment */
#define ACCESS_U 8 /* access unlocked: does not depend on global lock */ 
#define ACCESS_ALL (ACCESS_RW|ACCESS_I|ACCESS_U)

#define MAX_SLOT 8

struct slot_s
{
	unsigned char value;
	unsigned char access; 
};

struct info_s
{
  char           locked;
  char           error;
  unsigned char password[4];
  struct slot_s slot[MAX_SLOT];
};

static struct info_s info =
{
  .locked = 1,
  .error = 0,
  .password = "2304",
  .slot = {
	{'a', ACCESS_RW|ACCESS_U},
	{'b', ACCESS_RW|ACCESS_U},
	{'c', ACCESS_RW|ACCESS_U},
	{100, ACCESS_R|ACCESS_U},
	{'x', ACCESS_R|ACCESS_I|ACCESS_U},
	{'y', ACCESS_RW},
	{'z', ACCESS_R} }
};

static unsigned int clear_error()
{
	info.error = 0;
  return info.error;
}

static unsigned int set_error()
{
	info.error = -1;
  return info.error;
}

static unsigned int is_error()
{
	return info.error != 0;
}


static void lock(void)
{
  info.locked = 1;
}

static void unlock(void)
{
  info.locked = 0;
}

static int islocked(void)
{
  return info.locked;
}

static unsigned int is_slot_ok(int slot, unsigned int access)
{
	struct slot_s* s;
	if (slot < MAX_SLOT)
	{
		s = &info.slot[slot];
		if (s && (s->access & access))
      if(!islocked() || (s->access & ACCESS_U))
          return !clear_error(); /* granted */
	}
	return !set_error();
}

static unsigned char slot_read(int slot)
{
	if(is_slot_ok(slot, ACCESS_R))
		return info.slot[slot].value;
	else
		return 0;
}

unsigned int recursive_write_digit(unsigned char* value_ascii, unsigned int value_len, unsigned int index)
{
  unsigned int value;
  if(index > 0)
  {
    /* not yet reached the last digit */
    value = recursive_write_digit(value_ascii, value_len, index-1)*10 + (value_ascii[index] - '0');
  }
  else
  {
    /* this is the last digit */
    value = value_ascii[index] - '0';
  }  
  return value;
}

void slot_write(int slot, unsigned char* value_ascii, unsigned int value_len)
{
	if(is_slot_ok(slot, ACCESS_W))
	{
			//int i;
      info.slot[slot].value = recursive_write_digit(value_ascii, value_len, value_len - 1);
      /*
			for(i=0;i<value_len;i++)
				info.slot[slot].value = info.slot[slot].value*10 + value_ascii[i] - '0';*/
	}
}


void slot_increment(int slot)
{
	if(is_slot_ok(slot, ACCESS_I))
	{
      if (info.slot[slot].value < 255)
        info.slot[slot].value += 1;
	}
}


void slot_unlock(unsigned char* pw, int size)
{
  if(memcmp(info.password, pw, sizeof(info.password)) == 0)
  {
    unlock();
    clear_error();
  }
  else
  {
    lock();
    set_error();
  }
}

unsigned char get_access_symbol(unsigned char slotr, unsigned type, unsigned char symbol)
{
  if (slotr & type)
      return symbol;
  else 
    return '-';
}

static void print_status(void)
{
    unsigned char tmp;
    int slot;
    if(islocked())
              printf("device locked\n");
    else
              printf("device unlocked\n");
    
    for(slot=0;slot<MAX_SLOT;slot++)
    {
        tmp = info.slot[slot].access;
        printf("%d  %c%c%c%c\n", 
                slot,
                get_access_symbol(tmp,ACCESS_R,'R'), 
                get_access_symbol(tmp,ACCESS_W,'W'), 
                get_access_symbol(tmp,ACCESS_I,'I'), 
                get_access_symbol(tmp,ACCESS_U,'U') 
                );
    }
    clear_error();
}     

void print_help(void)
{
    printf("commands\n");
    printf("Rx: read value at slot x. ex R2\n");
    printf("Wxvvv: write value vvv at slot x. ex W137 writes 37 into slot 1\n");
    printf("Ix: increment value in slot x\n");
    printf("Uyyyy: unlock slots. yyyy is the password. ex 1234\n");
    printf("S: get status on slots\n");
}

/* API functions */

void slot_process_command(unsigned char* c, unsigned char size)
{
	unsigned char tmp;
  set_error();
	if (size>0)
	{
    switch(c[0])
    {
      case 'R': /* read slot command */
      case 'r': 
        if(size == 2)
        {
          tmp = slot_read(c[1]-'0');
          if (!is_error())
            printf("%d\n", tmp);
        }
        break;
      case 'W': /* write slot command */
      case 'w': 
        if(size > 2)
           slot_write(c[1]-'0', &c[2], size-2);
        break;
      case 'I': /* increment slot */
      case 'i': 
        if(size == 2)
           slot_increment(c[1]-'0');
        break;
      case 'S': /* get status*/
      case 's': 
        if(size == 1)
          print_status();
        break;
      case 'U': /* unlocks slots */
      case 'u': 
        //slot_unlock((char*)&c[1], strlen((char*)&c[1]));
        slot_unlock((unsigned char*)&c[1], strlen((char*)&c[1]));
        break;
      case 'H': /* help */
      case 'h': 
      default:
        printf("Rx: read value at slot x. ex R2\n");
        printf("Wxvvv: write value vvv at slot x. ex W137 writes 37 into slot 1\n");
        printf("Ix: increment value in slot x\n");
        printf("Uyyyyyyyy: unlock slots. yyyyy is the password. ex U1234\n");
        printf("S: get status on slots\n");
        break;
    }
	}
  if(is_error())
		printf("error\n");
  else
		printf("ok\n");
}


