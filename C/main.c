#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

// Constraints
#define MAX_CAPACITY 25
#define NUM_OVENS 4
#define NUM_CHEFS 4
#define SOFA_CAPACITY 4

// Durations (in simulated seconds)
#define T_CUSTOMER_ACTION 1
#define T_CHEF_ACTION 2

// Data for arrivals
typedef struct {
    long ts;   // arrival timestamp
    long id;   // customer id
} arrival_t;

// Customer state
typedef struct {
    long id;
    long arrival_ts;

    bool entered;
    bool seated;
    bool requested;
    bool baking;
    bool baked;
    bool paid;            // finished the "pays" action
    bool accept_started;  // chef started accepting payment
    bool done;            // left

    long t_sat;           // time they sat on sofa
    long t_request;       // time they requested cake
    long t_bake_start;
    long t_bake_end;
    long t_pay_time;      // time they started paying (equal to bake end)
    long t_accept_start;
    long t_accept_end;
    long t_leave;
} customer_t;

// Simple circular queue of indices into customers[]
typedef struct {
    int data[2048];
    int head, tail, size;
} queue_t;

static void q_init(queue_t *q){ q->head=q->tail=q->size=0; }
static bool q_empty(queue_t *q){ return q->size==0; }
static int q_size(queue_t *q){ return q->size; }
static void q_push(queue_t *q, int v){ q->data[q->tail++]=v; if(q->tail>=2048) q->tail=0; q->size++; }
static int q_front(queue_t *q){ return q->data[q->head]; }
static int q_pop(queue_t *q){ int v=q->data[q->head++]; if(q->head>=2048) q->head=0; q->size--; return v; }

// Globals
static arrival_t arrivals[1024];
static int num_arrivals=0;

static customer_t customers[1024];
static int num_customers=0; // equals num_arrivals after parsing

// Queues by index into customers[]
static queue_t standing_q;        // FIFO by entry time
static queue_t sofa_q;            // FIFO by sit time (reserved seats)
static queue_t accept_ready_q;    // FIFO by pay time (customers who finished paying and ready for accept at t+1)

// In-progress tasks
typedef struct {
    int cust_idx;
    int chef_id;     // 1..4
    long end_time;   // start_time + 2
} inprog_t;

static inprog_t baking[NUM_OVENS];
static int baking_cnt=0;

static inprog_t accepting; // only one at a time due to single register
static bool register_busy=false;

// Resources
static bool chef_free[NUM_CHEFS]; // true when free
static int ovens_available = NUM_OVENS;
static int people_inside = 0;

static long current_time = 0;

static int cmp_arrival(const void* a, const void* b){
    const arrival_t *x=a, *y=b;
    if(x->ts!=y->ts) return (x->ts<y->ts)?-1:1;
    if(x->id!=y->id) return (x->id<y->id)?-1:1;
    return 0;
}

static void read_input(){
    char buf[256];
    while(fgets(buf, sizeof(buf), stdin)){
        if(strstr(buf, "<EOF>")!=NULL) break;
        long ts=0, id=0;
        if(sscanf(buf, "%ld Customer %ld", &ts, &id)==2){
            arrivals[num_arrivals].ts=ts;
            arrivals[num_arrivals].id=id;
            num_arrivals++;
        }
    }
    qsort(arrivals, num_arrivals, sizeof(arrival_t), cmp_arrival);
    // Initialize customers array
    for(int i=0;i<num_arrivals;i++){
        customers[i].id = arrivals[i].id;
        customers[i].arrival_ts = arrivals[i].ts;
        customers[i].entered=false;
        customers[i].seated=false;
        customers[i].requested=false;
        customers[i].baking=false;
        customers[i].baked=false;
        customers[i].paid=false;
        customers[i].accept_started=false;
        customers[i].done=false;
        customers[i].t_sat=customers[i].t_request=customers[i].t_bake_start=customers[i].t_bake_end=-1;
        customers[i].t_pay_time=customers[i].t_accept_start=customers[i].t_accept_end=customers[i].t_leave=-1;
    }
    num_customers = num_arrivals;
}

static void print_customer(long id, const char *action){
    printf("%ld Customer %ld %s\n", current_time, id, action);
}
static void print_chef(int chef_id, const char *action_fmt, long cust_id){
    if(strcmp(action_fmt, "bakes for Customer") == 0){
        printf("%ld Chef %d bakes for Customer %ld\n", current_time, chef_id, cust_id);
    } else if(strcmp(action_fmt, "accepts payment for Customer") == 0){
        printf("%ld Chef %d accepts payment for Customer %ld\n", current_time, chef_id, cust_id);
    }
}

static int get_free_chef(){
    for(int i=0;i<NUM_CHEFS;i++) if(chef_free[i]) return i+1; // 1..4
    return 0;
}

// Global variable to track when a seat became free
static long last_seat_freed_time = -1;


static void finish_tasks_at_time(){
    // 1) Finish accepting (if any) whose end_time == current_time
    if(register_busy && accepting.end_time == current_time){
        int ci = accepting.cust_idx;
        // Chef finished accepting payment
        customers[ci].t_accept_end = current_time;
        customers[ci].accept_started = false;
        // The customer leaves now (payment accepted => leave)
        customers[ci].paid = true; // payment fully processed
        customers[ci].t_leave = current_time;
        customers[ci].done = true;
        print_customer(customers[ci].id, "leaves");
        // Free chef
        chef_free[accepting.chef_id-1] = true;
        register_busy = false;
        // Free capacity and remove from sofa (seat reserved was until leaving)
        people_inside--;

        last_seat_freed_time = current_time;

        // Rebuild sofa queue without this customer
        queue_t new_sofa; q_init(&new_sofa);
        while(!q_empty(&sofa_q)){
            int x = q_pop(&sofa_q);
            if(x!=ci) q_push(&new_sofa, x);
        }
        sofa_q = new_sofa;
    }

    // 2) Finish bakings that end now; multiple can finish simultaneously
    if(baking_cnt>0){
        inprog_t new_baking[NUM_OVENS];
        int nb=0;
        for(int i=0;i<baking_cnt;i++){
            if(baking[i].end_time == current_time){
                int ci = baking[i].cust_idx;
                // Baking done => customer can start "pays" action now (1s). We record pay start time.
                customers[ci].baked = true;
                customers[ci].baking = false;            // <-- important: clear baking flag
                customers[ci].t_bake_end = current_time;
                customers[ci].t_pay_time = current_time; // pays action starts now (duration 1s)
                // Log pay start at current_time
                print_customer(customers[ci].id, "pays");
                // push to accept-ready queue; accept can only start after pay completes (t_pay_time + T_CUSTOMER_ACTION)
                q_push(&accept_ready_q, ci);
                // Free chef and oven immediately
                chef_free[baking[i].chef_id-1] = true;
                ovens_available++;
            } else {
                new_baking[nb++] = baking[i];
            }
        }
        // copy remaining bakings back
        baking_cnt = nb;
        for(int i=0;i<nb;i++) baking[i]=new_baking[i];
    }
}

static void process_arrivals_at_time(int *arrival_idx){
    while(*arrival_idx < num_arrivals && arrivals[*arrival_idx].ts == current_time){
        if(people_inside >= MAX_CAPACITY){
            (*arrival_idx)++;
            continue;
        }
        int ci = *arrival_idx; // customers[] mirrors arrivals[] ordering
        customers[ci].entered = true;
        people_inside++;
        print_customer(customers[ci].id, "enters");
        // After entering, they can sit earliest at current_time+1 if seat available; put in standing queue now
        q_push(&standing_q, ci);
        (*arrival_idx)++;
    }
}


static void move_standing_to_sofa_if_possible(){
    // Move as many standing customers to sofa as seats available
    while(q_size(&sofa_q) < SOFA_CAPACITY && !q_empty(&standing_q)){
        int ci = q_front(&standing_q);
        long earliest_sit = customers[ci].arrival_ts + T_CUSTOMER_ACTION; // enter -> sit takes 1s

        // NEW: enforce 1-second delay after a seat is freed
        long delay_after_free = (last_seat_freed_time == -1) ? 0 : last_seat_freed_time + 1;
        long allowed_sit_time = (earliest_sit > delay_after_free) ? earliest_sit : delay_after_free;

        if(current_time < allowed_sit_time) break; // cannot sit yet

        q_pop(&standing_q);
        q_push(&sofa_q, ci);
        customers[ci].seated = true;
        customers[ci].t_sat = current_time;
        print_customer(customers[ci].id, "sits");
    }
}


static void make_requests_from_sofa(){
    // Customers request cake 1s after sitting. We must preserve sofa order.
    int n = q_size(&sofa_q);
    for(int k=0; k<n; k++){
        int ci = q_pop(&sofa_q);
        // Check request eligibility
        if(customers[ci].seated && !customers[ci].requested){
            if(current_time >= customers[ci].t_sat + T_CUSTOMER_ACTION){
                customers[ci].requested = true;
                customers[ci].t_request = current_time;
                print_customer(customers[ci].id, "requests cake");
            }
        }
        // push back to sofa to preserve order (they remain seated until they leave)
        q_push(&sofa_q, ci);
    }
}

static void schedule_accepts(){
    // Payment has priority. While register free, a free chef exists, and a paid customer finished paying in previous second, start accept.
    while(!register_busy){
        int chef_id = get_free_chef();
        if(chef_id==0) break;
        if(q_empty(&accept_ready_q)) break;
        int ci = q_front(&accept_ready_q);
        // Can only start accept after the customer's pay (1s) finished
        if(current_time < customers[ci].t_pay_time + T_CUSTOMER_ACTION) break;
        // start accept
        q_pop(&accept_ready_q);
        customers[ci].accept_started = true;
        customers[ci].t_accept_start = current_time;
        customers[ci].t_accept_end = current_time + T_CHEF_ACTION;
        register_busy = true;
        chef_free[chef_id-1] = false;
        accepting.cust_idx = ci;
        accepting.chef_id = chef_id;
        accepting.end_time = customers[ci].t_accept_end;
        print_chef(chef_id, "accepts payment for Customer", customers[ci].id);
    }
}

static void schedule_bakes(){
    // NOTE: Removed previous blocking checks so that free chefs can bake
    // even while the register is occupied or payments are pending.
    // Payment still has priority in the main loop because schedule_accepts()
    // is called before schedule_bakes().

    // While ovens and a chef are available, find the oldest-seated sofa customer who requested and start baking for them.
    while(ovens_available > 0){
        int chef_id = get_free_chef();
        if(chef_id==0) break;
        // Build a temp array of sofa order to find the first eligible requester
        int n = q_size(&sofa_q);
        if(n==0) break;
        int temp[SOFA_CAPACITY > 0 ? SOFA_CAPACITY : 4];
        int tn=0;
        for(int k=0;k<n;k++){
            int ci = q_pop(&sofa_q);
            temp[tn++] = ci;
            q_push(&sofa_q, ci);
        }
        int target_ci = -1;
        for(int i=0;i<tn;i++){
            int ci = temp[i];
            if(customers[ci].requested && !customers[ci].baking && !customers[ci].baked){
                if(current_time >= customers[ci].t_request + T_CUSTOMER_ACTION){
                    target_ci = ci;
                    break;
                }
            }
        }
        if(target_ci == -1) break; // no eligible requester

        // Start baking for target but DO NOT remove the customer from the sofa (seat remains reserved until leaving)
        customers[target_ci].baking = true;
        customers[target_ci].t_bake_start = current_time;
        customers[target_ci].t_bake_end = current_time + T_CHEF_ACTION;
        // allocate baking slot
        baking[baking_cnt].cust_idx = target_ci;
        baking[baking_cnt].chef_id = chef_id;
        baking[baking_cnt].end_time = customers[target_ci].t_bake_end;
        baking_cnt++;
        ovens_available--;
        chef_free[chef_id-1] = false;
        print_chef(chef_id, "bakes for Customer", customers[target_ci].id);
    }
}

int main(){
    read_input();

    q_init(&standing_q);
    q_init(&sofa_q);
    q_init(&accept_ready_q);
    for(int i=0;i<NUM_CHEFS;i++) chef_free[i]=true;
    ovens_available = NUM_OVENS;
    register_busy = false;
    accepting.cust_idx = -1;
    accepting.chef_id = -1;
    accepting.end_time = -1;

    if(num_arrivals==0) return 0;
    current_time = arrivals[0].ts; // start at first arrival time

    int arrival_idx = 0;

    // Simulation loop: advance one second at a time until all done
    while(1){
        // === Process arrivals first
        process_arrivals_at_time(&arrival_idx);

        // Finish tasks ending now (accepts first -> frees seat; bakings -> customers pay)
        finish_tasks_at_time();

        move_standing_to_sofa_if_possible();
        make_requests_from_sofa();
        schedule_accepts();
        schedule_bakes();

        // Termination condition
        bool any_in_progress = register_busy || (baking_cnt>0);
        bool queues_nonempty = (people_inside>0) || (arrival_idx < num_arrivals) || !q_empty(&standing_q) || !q_empty(&sofa_q) || !q_empty(&accept_ready_q);
        if(!any_in_progress && !queues_nonempty){
            break;
        }

        // Advance time by one second
        current_time++;
    }

    return 0;
}
