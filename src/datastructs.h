#pragma once

//For overloading list_loop
#define GET_MACRO(_1, _2, _3, _4, NAME, ...) NAME

//For overloading list_cleanup
#define GET_MACRO2(_1, _2, _3, NAME, ...) NAME

//Linked list macros
//Adds to_link directly in front of current
#define link(current, to_link) ({\
	if (current == NULL)\
		current = to_link;\
	if (current->next)\
	{\
		to_link->next = current->next;\
		current->next = to_link;\
	}\
	else\
	{\
		to_link->next = current;\
		current->next = to_link;\
	}\
})
//Removes next element from list
#define unlink_next(current) ({\
	void* next_cpy = current->next;\
	current->next = current->next->next;\
	free (next_cpy);\
})

//Cleans up a list's memory
#define list_cleanup2(to_cleanup, callback) ({\
	while (to_cleanup->next != to_cleanup && to_cleanup->next)\
	{\
		callback (to_cleanup->next);\
		unlink_next (to_cleanup);\
	}\
	callback (to_cleanup);\
	free (to_cleanup);\
})

#define list_cleanup1(to_cleanup, callback, param) ({\
	while (to_cleanup->next != to_cleanup && to_cleanup->next)\
	{\
		callback (to_cleanup->next, param);\
		unlink_next (to_cleanup);\
	}\
	callback (to_cleanup, param);\
	free (to_cleanup);\
})

#define list_cleanup(args...) GET_MACRO2(args, list_cleanup1, list_cleanup2)(args)

//Calls function callback with every element in the list between start and end. Will loop through entire list if end and start are the same
#define list_loop1(callback, end, start, param) ({\
	void* end_cpy = end;\
	do\
	{\
		callback (start, param);\
		start = start->next;\
	} while (start != end_cpy && start);\
	start = end_cpy;\
})

#define list_loop2(callback, end, start) ({\
	void* end_cpy = end;\
	do\
	{\
		callback (start);\
		start = start->next;\
	} while (start != end_cpy && start);\
	start = end_cpy;\
})

#define list_loop(args...) GET_MACRO(args, list_loop1, list_loop2)(args)

