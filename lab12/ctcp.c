/******************************************************************************
 * ctcp.c
 * ------
 * Implementation of cTCP done here. This is the only file you need to change.
 * Look at the following files for references and useful functions:
 *   - ctcp.h: Headers for this file.
 *   - ctcp_iinked_list.h: Linked list functions for managing a linked list.
 *   - ctcp_sys.h: Connection-related structs and functions, cTCP segment
 *                 definition.
 *   - ctcp_utils.h: Checksum computation, getting the current time.
 *
 *****************************************************************************/

#include "ctcp.h"
#include "ctcp_linked_list.h"
#include "ctcp_sys.h"
#include "ctcp_utils.h"
#define DEBUG 0
#define MAX_BUFF_SIZE MAX_SEG_DATA_SIZE
#define SEGMENT_HDR_SIZE sizeof(ctcp_segment_t)

enum conn_state {
  DATA_TRANSFER,
  WAIT_TO_SEND_FIN,
  TEAR_DOWN,
  WAIT_LAST_ACK,
  WAIT_LAST_FIN,
};

enum keyword {
  ACKNO,
  SEQNO,
};

struct segment_attr {
  uint16_t no_of_times;           /* Number of retransmission */
  uint16_t time;                 /* Use for retransmission timeout counting */
  uint16_t datalen;              /* Datalength of sent segment */
  ctcp_segment_t *segment;
};

typedef struct segment_attr ctcp_segment_attr_t;
typedef enum conn_state conn_state_t;
typedef enum keyword keyword_t;


char buffer_out[MAX_BUFF_SIZE];


/**
 * Connection state.
 *
 * Stores per-connection information such as the current sequence number,
 * unacknowledged packets, etc.
 *
 * You should add to this to store other fields you might need.
 */
struct ctcp_state {
  struct ctcp_state *next;  /* Next in linked list */
  struct ctcp_state **prev; /* Prev in linked list */

  conn_t *conn;             /* Connection object -- needed in order to figure
                               out destination when sending */
  linked_list_t *segments_send;  /* Linked list of segments sent to this connection.
                               It may be useful to have multiple linked lists
                               for unacknowledged segments, segments that
                               haven't been sent, etc. Lab 1 uses the
                               stop-and-wait protocol and therefore does not
                               necessarily need a linked list. You may remove
                               this if this is the case for you */
  

  /* FIXME: Add other needed fields. */
  linked_list_t *segments_receive;
  conn_state_t conn_state;
  uint32_t seqno;               /* Current sequence number */
  uint32_t ackno;               /* Current ack number */
  uint32_t base_seqno;          /* Base sequence number: seqno of the first segment in the send linked list */
  uint16_t recv_window;         /* receiving window size */
  uint16_t send_window;         /* sending window size */
  
  uint16_t datasize_in;         /* Size of data in the input window */
  uint16_t datasize_out;        /* Size of data in the output window */
  uint16_t timer;               /* How often ctcp_timer() is called, in ms */
  uint16_t rt_timeout;          /* Retransmission timeout, in ms */
  
  bool     wait_destroy;        /* TRUE indicate starting 2*MSL timeout */
  uint16_t tim;                 /* Use for 2*MSL timeout counting */
  uint32_t fin_ackno;           /* ACK number of the first FIN segment */
  uint32_t fin_seqno;           /* SEQ number of the first FIN segment */
};

/**
 * Linked list of connection states. Go through this in ctcp_timer() to
 * resubmit segments and tear down connections.
 */
static ctcp_state_t *state_list;

/* FIXME: Feel free to add as many helper functions as needed. Don't repeat
          code! Helper functions make the code clearer and cleaner. */

/**
 * The two following funtions convert the byte-order of segments
 */
static void _segment_hton(ctcp_segment_t *segment)
{
  segment->seqno = htonl(segment->seqno);
  segment->ackno = htonl(segment->ackno);
  segment->len = htons(segment->len);
  segment->flags = htonl(segment->flags);
  segment->window = htons(segment->window);
  /* cksum is already in network byte order - README said */

}
static void _segment_ntoh(ctcp_segment_t *segment)
{
  segment->seqno = ntohl(segment->seqno);
  segment->ackno = ntohl(segment->ackno);
  segment->len = ntohs(segment->len);
  segment->flags = ntohl(segment->flags);
  segment->window = ntohs(segment->window);
}

/**
 * Save the sent segment to a linked list of segments with attributes include:
 *  timer counter, number of attempts, and segments' data length
 */
static void _save_sent_segment(ctcp_state_t *state, ctcp_segment_t *sent_segment)
{
  ctcp_segment_attr_t *sent_segment_attr;

  sent_segment_attr = calloc(sizeof(ctcp_segment_attr_t),1);
  sent_segment_attr->time = 0;
  sent_segment_attr->no_of_times = 0;
  sent_segment_attr->segment = sent_segment;
  sent_segment_attr->datalen = ntohs(sent_segment->len) - SEGMENT_HDR_SIZE;

  state->datasize_out += sent_segment_attr->datalen;
  ll_add(state->segments_send,(void *)sent_segment_attr);
}

/**
 * Save received segment to linked list:
 *  - Locate the received segment in the linked list.
 *  - Add the received segment in the right position.
 * 
 * Received segment members are in host byte order
 */
static void _save_received_segment(ctcp_state_t *state, ctcp_segment_t *received_segment)
{
  ctcp_segment_t *segment;
  ll_node_t *ll_node;
  uint32_t received_seqno;

  ll_node = state->segments_receive->head;
  received_seqno = received_segment->seqno;

  while (NULL != ll_node)
  {
    segment = (ctcp_segment_t *)ll_node->object;

    if (segment->seqno > received_seqno)
      break;

    ll_node = ll_node->next;
  }

  if (NULL == ll_node)
  {
    ll_add(state->segments_receive,received_segment);
  }
  else
    if (ll_node == state->segments_receive->head)
    {
      ll_add_front(state->segments_receive,received_segment);
    }
  else
  {
    ll_add_after(state->segments_receive,ll_node->prev,received_segment);
  }

  state->datasize_in += received_segment->len - SEGMENT_HDR_SIZE;
}

static int16_t _segment_send(ctcp_state_t *state,int32_t flags, int32_t len, char* data)
{
  int32_t datalen;
  datalen = len - SEGMENT_HDR_SIZE;
  ctcp_segment_t *segment = calloc(len,1);
  segment->len = len;
  segment->seqno = state->seqno;
  segment->ackno = state->ackno;
  segment->flags = flags;
  segment->window = state->recv_window;
  memcpy(segment->data,data,datalen);
  _segment_hton(segment);
  segment->cksum = 0;
  int32_t sum = cksum(segment,len);
  segment->cksum = sum;
  if(conn_send(state->conn,segment,len) < 0)
  {
    return -1;
  }
 
  if (flags & FIN)
  {
    state->seqno ++;
    state->fin_seqno = state->seqno;
    state->fin_ackno = state->ackno;
  }
  else
  {
    state->seqno += datalen;
  }

  if (datalen > 0)
    _save_sent_segment(state,segment);
  return len;
}

/**
 * Check if the segment is not corrupted or truncated.
 * 
 * Return  0  if the segment is valid
 *        -1  if the segment is corrupted or truncated
 */
static int16_t _is_segment_valid(ctcp_segment_t *segment,uint16_t len)
{
  uint16_t sum;
  /* Check if segment is truncated */
  if(ntohs(segment->len) > len)
  { 
    return -1;
  }
  /* Check if segment is corrupted */
  sum = segment->cksum;
  segment->cksum = 0;
  if(cksum(segment, ntohs(segment->len)) != sum)
  {
    return -1;
  }
  return 0;
}

/**
 * Find a segment in a linked list of segment attributes base on the key
 *   - ll_list: linked list of segment attributes (Ex: state->segment_send)
 *   - key    : ACKNO or SEQNO
 *   - number : ack number or sequence number of segment to find
 * Return:    Pointer to ll_node of segment attributes matched with ackno or seqno to find
 *            NULL if found no segment
 */
ll_node_t *_find_segment_ll_node(linked_list_t *ll_list,keyword_t key,uint32_t number)
{
  ll_node_t *ll_node;
  ctcp_segment_attr_t *segment_attr;
  ll_node = ll_list->head;
  switch (key)
  {
    case ACKNO:
    {
      while(NULL != ll_node)
      {
        segment_attr = (ctcp_segment_attr_t *)ll_node->object;
        
        if(ntohl(segment_attr->segment->ackno) == number)
          return ll_node;
        else ll_node = ll_node->next;
      }
      break;
    }
    case SEQNO:
    {
      while(NULL != ll_node)
      {
        segment_attr = (ctcp_segment_attr_t *)ll_node->object;
        
        if(ntohl(segment_attr->segment->seqno) == number)
          return ll_node;
        else ll_node = ll_node->next;
      }
      break;
    }
  }
  return NULL;
}


/**
 * Destroy segment:
 * Find the segment with ackno/seqno in segments_send linked list, free and nullify the segment but still hold
 * segment's node in the linked list
 * 
 * Check from head and delete the nullified segments.
 * 
 *  state : state structure
 *  key   : ACKNO or SEQNO
 *  number: ack or sequence number of the segment to be destroy
 * 
 *  return: number of removed linked list node (0 if the destroyed segment is not at the head of the linked list)
**/
static int _destroy_segment_attr(ctcp_state_t *state,keyword_t key, uint32_t number)
{
  int ret = 0;
  ll_node_t *ll_node;
  ctcp_segment_attr_t *sent_segment_attr;
  
  ll_node = _find_segment_ll_node(state->segments_send,key,number);
  if (NULL == ll_node)
  {
    return ret;
  }
  sent_segment_attr = (ctcp_segment_attr_t *)ll_node->object;
  free(sent_segment_attr->segment);
  sent_segment_attr->segment = NULL;

  ll_node = state->segments_send->head;
  sent_segment_attr = (ctcp_segment_attr_t *)ll_node->object;
  while(NULL == sent_segment_attr->segment)
  {
    state->datasize_out -= sent_segment_attr->datalen;
    free(sent_segment_attr);
    ll_remove(state->segments_send,ll_node);

    ret++;

    ll_node = state->segments_send->head;
    if (NULL == ll_node)
      break;
    sent_segment_attr = (ctcp_segment_attr_t *)ll_node->object;
  }

  ll_node = state->segments_send->head;
  if (NULL != ll_node)
  {
    sent_segment_attr = (ctcp_segment_attr_t *)ll_node->object;
    state->base_seqno = sent_segment_attr->segment->seqno;
  }

  return ret;
}

/**
 * Destroy the linked list of sent segments
 * Because the segments are wrapped in the struct segment_attr, segments must be freed 
 * before the segment_attr structs are freed
 */
static void _destroy_ll_sent_segments(ctcp_state_t *state)
{
  ll_node_t *ll_node;
  ctcp_segment_attr_t *segment_attr;
  
  ll_node = state->segments_send->head;

  while (NULL != ll_node)
  {
    segment_attr = (ctcp_segment_attr_t *)ll_node->object;
    free(segment_attr->segment);
    segment_attr->segment = NULL;
  }

  ll_destroy(state->segments_send);
}

/**
 * Timer handler for each connection state
 */
void timer_handler(ctcp_state_t *state)
{

  if (state->wait_destroy == 1)
  {
    state->tim += state->timer;
      if(state->tim >= (state->rt_timeout)*50)
      {
        ctcp_destroy(state);
        return;
      }
  }

  ll_node_t *ll_node;
  ctcp_segment_attr_t *segment_attr;
  ll_node = state->segments_send->head;
  while(ll_node != NULL) 
  {
    segment_attr = (ctcp_segment_attr_t *)ll_node->object;
    segment_attr->time += state->timer;
    if(segment_attr->time >= state->rt_timeout)
    {
      conn_send(state->conn,segment_attr->segment,ntohs(segment_attr->segment->len));
      segment_attr->no_of_times ++;
      segment_attr->time = 0;
      if(segment_attr->no_of_times >= 5)
      {
        ctcp_destroy(state);
        break;
      }
      else
      {
        ll_node = ll_node->next;
      }

      if ((state->conn_state == WAIT_TO_SEND_FIN) && (state->segments_send->length == 0))
      {
        state->conn_state = WAIT_LAST_ACK;
      }
    }
    else
    {
      ll_node = ll_node->next;
    }
  }
}

ctcp_state_t *ctcp_init(conn_t *conn, ctcp_config_t *cfg)
{
  /* Connection could not be established. */
  if (conn == NULL) {
    return NULL;
  }

  /* Established a connection. Create a new state and update the linked list
     of connection states. */
  ctcp_state_t *state = calloc(sizeof(ctcp_state_t), 1);
  state->next = state_list;
  state->prev = &state_list;
  if (state_list)
    state_list->prev = &state->next;
  state_list = state;

  /* Set fields. */
  state->conn = conn;
  /* FIXME: Do any other initialization here. */

  state->ackno = 1;
  state->seqno = 1;
  state->base_seqno = 1;

  state->recv_window = cfg->recv_window;
  state->send_window = cfg->send_window;
  state->datasize_in = 0;
  state->datasize_out = 0;

  state->tim = 0;
  state->timer = cfg->timer;
  state->rt_timeout = cfg->rt_timeout;

  state->conn_state = DATA_TRANSFER;
  state->wait_destroy = 0;

  state->segments_send = ll_create();
  state->segments_receive = ll_create();

  free(cfg);
  return state;
}

void ctcp_destroy(ctcp_state_t *state)
{
  /* Update linked list. */
  if (state->next)
    state->next->prev = state->prev;

  *state->prev = state->next;
  conn_remove(state->conn);

  /* FIXME: Do any other cleanup here. */

  _destroy_ll_sent_segments(state);
  ll_destroy(state->segments_receive);
  
  free(state);

  state = NULL;
  end_client();
}

void ctcp_read(ctcp_state_t *state) {
  /* FIXME */
  uint32_t retval, len, flags = 0;
  bzero(buffer_out, MAX_BUFF_SIZE);
  retval = conn_input(state->conn, buffer_out, MAX_BUFF_SIZE);

  if (-1 == retval) 
  {
    flags = FIN;
    if(_segment_send(state, flags, SEGMENT_HDR_SIZE, NULL) < 0)
    {
      goto exit_read;
    }
  }
  else
  {
    len = retval + SEGMENT_HDR_SIZE;
    flags = ACK;
    if((retval=_segment_send(state, flags, len, buffer_out)) < 0)
    {
      
    }
  }
exit_read: return;
}

void ctcp_receive(ctcp_state_t *state, ctcp_segment_t *segment, size_t len) {
  /* FIXME */
  fprintf(stderr,"Received segment:\n");
  _print_segment_info(segment);  
  fprintf(stderr,"\n");
  if(_is_segment_valid(segment,(uint16_t)len) != 0)
  {
    fprintf(stderr, "Received segment is invalid \n");
    goto exit_receive;
  }

  _segment_ntoh(segment);

  if (state->conn_state == DATA_TRANSFER)
  {
    if((segment->ackno < state->seqno) || (segment->seqno < state->ackno))
    {
      goto exit_receive;
    }
    if(segment->flags & FIN)
    {
      if(DEBUG)
        fprintf(stderr,"Send ACK of FIN segment\n");
/* Send EOF to STDOUT */
      conn_output(state->conn,NULL,0);
      state->ackno = segment->seqno + 1;
      if(_segment_send(state,ACK,SEGMENT_HDR_SIZE,NULL) < 0)
      {
        perr("Cannot send ACK of FIN segment");
      }
      if(DEBUG)
        fprintf(stderr,"Send FIN segment\n");
/* Send FIN/ACK segment back */
      if(_segment_send(state,FIN,SEGMENT_HDR_SIZE,NULL) < 0)
      {
        perr("Cannot send FIN segment");
      }
      state->conn_state = WAIT_LAST_ACK;
    }
    else if (segment->flags & ACK)
    {
      if(segment->len == SEGMENT_HDR_SIZE)
      {
        state->ackno = segment->seqno;
        _destroy_acked_segment(state);
        free(segment);
      }
      else{
/*Send data to STDOUT */
      state->received_segment = segment;
      ctcp_output(state);
      }
    }
  }
  if(state->conn_state == TEAR_DOWN)
  {
    if(segment->flags & ACK)
      state->conn_state = WAIT_LAST_FIN;
  }
  if(state->conn_state == WAIT_LAST_FIN)
  {
    if(segment->flags & WAIT_LAST_FIN)
      ctcp_destroy(state);
  }
  if(state->conn_state == WAIT_LAST_ACK)
  {
    if(segment->flags & ACK)
      ctcp_destroy(state);
  }

exit_receive: return;
}

void ctcp_output(ctcp_state_t *state) {
  uint32_t avail_buf,datalen;
  datalen = state->received_segment->len - SEGMENT_HDR_SIZE;
  avail_buf = conn_bufspace(state->conn);
  if (avail_buf == 0)
  {
    fprintf(stderr,"No available buffer \n");
    free(state->received_segment);
    return;
  }
  if(avail_buf >= datalen)
  {
   // fprintf(stderr,"%s",state->received_segment->data);
    if(conn_output(state->conn,state->received_segment->data,datalen) < 0)
    {
      fprintf(stderr,"Cannot output\n");
      ctcp_destroy(state);
      return;
    }
    /*Send ACK segment*/
    state->ackno = state->received_segment->seqno + datalen;
    if(_segment_send(state,ACK,SEGMENT_HDR_SIZE,NULL) < 0)
    {
      perr("Cannot send ACK segment\n");
    }
    _destroy_acked_segment(state);
    free(state->received_segment);
  }
}

void ctcp_timer() {
  /* FIXME */
  ctcp_state_t *state = state_list;
  while(NULL != state)
  {
    retransmission_handler(state);
    state = state_list->next;
  }
}
