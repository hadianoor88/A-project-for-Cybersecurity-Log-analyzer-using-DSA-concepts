// A-project-for-Cybersecurity-Log-analyzer-using-DSA-concepts
//A simple log analyzer using concept of Queues
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

// Log 
struct Log {
    int ID;
    char AttackType[50];
    int severity; //severity level
};

//Node for data of logs 
struct Node {
    struct Log  l;
    struct Node *next;
};

struct Node *front= NULL; //pointer to front of queue
struct Node *rear =NULL;  //pointer to the last element in queue

// enqueue function
void enqueue(int id, char aT[50], int svr){
    
    struct Node *newNode = (struct Node*)malloc(sizeof(struct Node));
    if (newNode == NULL) {
        printf("Memory allocation failed.\n");
        exit(1);   
    }
    newNode->l.ID= id;
    strcpy(newNode->l.AttackType, aT);
    newNode->l.severity= svr;
    newNode->next = NULL;
    if (front == NULL && rear == NULL){
        front = rear = newNode;
    }
    else {
        rear->next = newNode;
        rear = newNode;
    }
}

// dequeue function
void dequeue(){
    if (front == NULL){
        printf("The queue is empty \n");
    }
    else {
        struct Node *temp = front;
        printf("Removed the attack type with id : %d \n", temp->l.ID);
        front = front->next;
        if (front == NULL){
            // only if front after moving forward starts to point to NULL
            // special case for removing the last node
            rear = NULL; 
        }
        free(temp);
    }
}

void display(){
    struct Node *temp= front;
    // FIX 1: added empty queue check before displaying
    if (front == NULL){
        printf("There is nothing to show \n");
    }
    else {
        while (temp != NULL){
            printf("\nID: %d\n", temp->l.ID);
            printf("Attack Type: %s\n", temp->l.AttackType);
            printf("Severity: %d\n\n", temp->l.severity);
            temp = temp->next;
        }
    }
}

void searchLog() {
    int Id;
    printf("Enter the ID for log: ");
    scanf("%d", &Id);

    struct Node *temp = front;
    // FIX 2: position starts at 1 (not 0) so first log shows position 1
    int count = 1;
    int found = 0;

    while (temp != NULL) {
        if (temp->l.ID == Id) {
            printf("\nID: %d\n", temp->l.ID);
            printf("Attack Type: %s\n", temp->l.AttackType);
            printf("Severity: %d\n", temp->l.severity);
            printf("This is at position %d\n\n", count);
            found = 1;
            break; 
        }
        temp = temp->next;
        // FIX 3: count increments after moving to next node (was before)
        count++;
    }

    if (!found) {
        printf("No log found with ID %d\n", Id);
    }
}

void ShowStats(){
    // FIX 4: added empty queue check
    if (front == NULL){
        printf("No logs available.\n");
        return;
    }

    struct Node *temp = front;
    int total = 0;
    int low = 0;
    int medium = 0;
    int high = 0;
    int critical = 0;

    while (temp != NULL){
        if (temp->l.severity == 1){
            low++;
        }
        else if (temp->l.severity == 2 || temp->l.severity == 3){
            medium++;
        }
        else if (temp->l.severity == 4){
            high++;
        }
        else if (temp->l.severity == 5){
            critical++;
        }
        total++;
        temp = temp->next;
    }

    printf("Total logs: %d\n", total);
    printf("Level 1 (Low): %d\n", low);
    printf("Level 2-3 (Medium): %d\n", medium);
    printf("Level 4 (High): %d\n", high);
    printf("Level 5 (Critical): %d\n", critical);

    if (critical >= 3){
        printf("WARNING: Critical attacks reached or exceeded 3!\n");
    }
} 

void generateReport(){     
    struct Node *temp= front;    

    // FIX 5: added empty queue check
    if (front == NULL){
        printf("No logs available.\n");
        return;
    }

    int FailedLogin=0;    
    int PortScan=0;   
    int MalwareAlert=0;    
    int BruteForce=0;   
    int SuspiciousIP=0;     
    int total=0;

    while (temp != NULL){
        // FIX 6: removed '!' from strings and fixed capitalisation
        // so they match what the user actually types
        if (strcmp(temp->l.AttackType, "Failed Login")==0){
            FailedLogin++;
        }
        else if (strcmp(temp->l.AttackType, "Port Scan")==0){
            PortScan++;
        }
        else if (strcmp(temp->l.AttackType, "Malware Alert")==0){
            MalwareAlert++;
        }
        else if (strcmp(temp->l.AttackType, "Brute Force")==0){
            BruteForce++;
        }
        else if (strcmp(temp->l.AttackType, "Suspicious IP")==0){
            SuspiciousIP++;
        }
        temp=temp->next;
        total++;
    }
    printf("Number of total attacks: %d \n",total);
    printf("Number of Failed logins: %d \n",FailedLogin);
    printf("Number of Port Scans: %d \n",PortScan);
    printf("Number of Malware attacks: %d \n",MalwareAlert);
    printf("Number of Brute Force attacks : %d \n",BruteForce);
    printf("Number of Suspicious IP: %d \n",SuspiciousIP);
}

// FIX 7: added missing showCritical function
void showCritical(){
    if (front == NULL){
        printf("No logs available.\n");
        return;
    }
    struct Node *temp = front;
    int found = 0;
    printf("\n--- Critical Logs (Severity 5) ---\n");
    while (temp != NULL){
        if (temp->l.severity == 5){
            printf("ID: %d | %s\n", temp->l.ID, temp->l.AttackType);
            found = 1;
        }
        temp = temp->next;
    }
    if (!found){
        printf("No critical logs found.\n");
    }
}

void FreeMemory(){
    while (front != NULL){
        struct Node *temp =front;
        front= front->next;
        free(temp);
    }
}

int main(){
    int choice;
    do {
        printf("-----------------------------\n");
        printf("CYBER ATTACK LOG ANALYZER \n");
        printf("-----------------------------\n");
        printf("1. Add Security Log \n");
        printf("2. Process Oldest Log\n");
        printf("3. Display All logs \n");
        printf("4. Search Log by ID \n");
        printf("5. Show statistics\n");
        printf("6. Generate daily report\n");
        // FIX 8: added showCritical option to menu
        printf("7. Show Critical Logs\n");
        printf("8. Exit! \n");
        printf("Enter choice: \n");
        scanf("%d", &choice);

        if (choice == 1){
            int id, svr;
            char aT[50];
            printf("Enter ID: ");
            scanf("%d", &id);
            printf("Enter Attack Type: ");
            getchar();  // clears leftover newline
            fgets(aT, 50, stdin);
            aT[strcspn(aT, "\n")] = 0;  // remove newline
            printf("Enter Severity: ");
            scanf("%d", &svr);
            enqueue(id, aT, svr);
        }
        else if (choice == 2){
            dequeue();
        }
        else if (choice == 3){
            display();
        }
        else if (choice == 4){
            searchLog();
        }
        else if (choice == 5){
            ShowStats();
        }
        else if (choice == 6){
            generateReport();
        }
        // FIX 8 continued: wired showCritical to menu option 7
        else if (choice == 7){
            showCritical();
        }

    } while (choice != 8);
    FreeMemory();
    return 0;
}
