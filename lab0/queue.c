/* 
 * Code for basic C skills diagnostic.
 * Developed for courses 15-213/18-213/15-513 by R. E. Bryant, 2017
 * Modified to store strings, 2018
 */

/*
 * This program implements a queue supporting both FIFO and LIFO
 * operations.
 *
 * It uses a singly-linked list to represent the set of queue elements
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "harness.h"
#include "queue.h"

/*
  Create empty queue.
  Return NULL if could not allocate space.
*/
queue_t *q_new()
{
    queue_t *q =  malloc(sizeof(queue_t));
    /* What if malloc returned NULL? */
    if(!q)
	    return NULL;
q->head = NULL;
    q->tail = NULL;
    q->size = 0;
    return q;
}

/* Free all storage used by queue */
void q_free(queue_t *q)
{
    /* How about freeing the list elements and the strings? */
    /* Free queue structure */

    if(!q)
	    return;

    if(!q->head)
	    goto free_q;

    list_ele_t *ele = q->head;
    list_ele_t *next = NULL;

    while(ele){
	next = ele->next;
    	free(ele->value);
	free(ele);
	ele = next;
    }

free_q:
    free(q);
}

/*
  Attempt to insert element at head of queue.
  Return true if successful.
  Return false if q is NULL or could not allocate space.
  Argument s points to the string to be stored.
  The function must explicitly allocate space and copy the string into it.
 */
bool q_insert_head(queue_t *q, char *s)
{
    if(!q)
	    return false;

    list_ele_t *newh;
    /* What should you do if the q is NULL? */
    newh = malloc(sizeof(list_ele_t));
    if(!newh)
	    return false;
    newh->next = NULL;

    /* Don't forget to allocate space for the string and copy it */
    /* What if either call to malloc returns NULL? */
    size_t s_len = strlen(s);
    newh->value = malloc(s_len + 1);
    if(!newh->value){
    	free(newh);
	return false;
    }
    strncpy(newh->value, s, s_len);
    newh->value[s_len] = 0;

    if(0 == q->size){
    	q->head = newh;
	q->tail = newh;
	goto add_ele;
    }

    newh->next = q->head;
    q->head = newh;

add_ele:
    q->size++;
    return true;
}


/*
  Attempt to insert element at tail of queue.
  Return true if successful.
  Return false if q is NULL or could not allocate space.
  Argument s points to the string to be stored.
  The function must explicitly allocate space and copy the string into it.
 */
bool q_insert_tail(queue_t *q, char *s)
{
    /* You need to write the complete code for this function */
    /* Remember: It should operate in O(1) time */
    if(!q)
	    return false;

    list_ele_t *newt;
    newt = malloc(sizeof(list_ele_t));
    if(!newt)
	    return false;
    newt->next = NULL;
    size_t s_len = strlen(s);
    newt->value = malloc(s_len + 1);
    if(!newt->value){
    	free(newt);
	return false;
    }
    strncpy(newt->value, s, s_len);
    newt->value[s_len] = 0;

    if(0 == q->size){
	q->tail = newt;
    	q->head = newt;
	goto add_ele;
    }

    q->tail->next = newt;
    q->tail = newt;

add_ele:
    q->size++;
    return true;
}

/*
  Attempt to remove element from head of queue.
  Return true if successful.
  Return false if queue is NULL or empty.
  If sp is non-NULL and an element is removed, copy the removed string to *sp
  (up to a maximum of bufsize-1 characters, plus a null terminator.)
  The space used by the list element and the string should be freed.
*/
bool q_remove_head(queue_t *q, char *sp, size_t bufsize)
{
    /* You need to fix up this code. */
    if(!q || !q->head)
	    return false;

    list_ele_t *head_old = q->head;

    if(sp){
	    size_t value_len = strlen(head_old->value);
	    if(value_len > (bufsize - 1))
		value_len = bufsize - 1;

	    strncpy(sp, head_old->value, value_len);
	    sp[value_len] = 0;
    }

    if(1 == q->size){
	q->head = q->tail = NULL;	
	goto free_ele;
    }

    q->head = head_old->next;

free_ele:
    free(head_old->value);
    free(head_old);
    q->size--;
    return true;
}

/*
  Return number of elements in queue.
  Return 0 if q is NULL or empty
 */
int q_size(queue_t *q)
{
    /* You need to write the code for this function */
    /* Remember: It should operate in O(1) time */
    if(!q || !q->head)
	    return 0;

    return q->size;
}

/*
  Reverse elements in queue
  No effect if q is NULL or empty
  This function should not allocate or free any list elements
  (e.g., by calling q_insert_head, q_insert_tail, or q_remove_head).
  It should rearrange the existing ones.
 */
void q_reverse(queue_t *q)
{
    /* You need to write the code for this function */
    if(!q || !q->head)
	    return;

    size_t size = q_size(q);

    if(size == 1)
	    return;

    list_ele_t *ptr = q->head;
    list_ele_t *qtr = ptr->next;
    list_ele_t *rtr = NULL;

    for(size_t i = 0; i < size - 1; i++){
	rtr = qtr->next;
	qtr->next = ptr;
	ptr = qtr;
	qtr = rtr;
    }

    q->head->next = NULL;
    q->tail = q->head;
    q->head = ptr;          // ptr here is tail
}

