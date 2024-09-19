#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FILENAME "passwords.txt"
#define MAX_LINE 256

// Simple hash function
unsigned long hash(char *str) { // We define the return value beofre we start the function
    unsigned long hash = 5381; // We start with a hash value of 5381
    int c; // We define a variable to store each character

    while((c = *str++)) // We loop through each character of the string ( we point to the address memory of the string with *str and then move to the next character with ++)
        hash = ((hash << 5) + hash) + c; // We do something like hash = (hash * 32) + hash + c, ( 32 is 2^5, then we add the hash to the result and then add the character)

    return hash;
}

// Function to save the password to the file 
void save_password(char *username, unsigned long hashed_password){
    FILE *file = fopen(FILENAME, "a");
    if(file == NULL) {
        printf("Error opening file! \n");
        return;
    }

    fprintf(file, "%s:%lu\n", username, hashed_password);
    fclose(file);
}

unsigned long get_password(char *username) {
    FILE *file = fopen(FILENAME, "r");
    if (file == NULL) {
        printf("Error opening file!\n");
        return 0;
    }

    char line[MAX_LINE];
    char stored_username[MAX_LINE];
    unsigned long stored_password;

    while (fgets(line, sizeof(line), file)) {
        sscanf(line, "%[^:]:%lu", stored_username, &stored_password);
        if (strcmp(username, stored_username) == 0) {
            fclose(file);
            return stored_password;
        }
    }

    fclose(file);
    return 0;  // Return 0 if username not found
}

int main() {
    char choice;
    char username[MAX_LINE];
    char password[MAX_LINE];
    unsigned long hashed_password;

    while (1) {
        printf("\nPassword Manager\n");
        printf("1. Add new password\n");
        printf("2. Get existing password\n");
        printf("3. Exit\n");
        printf("Enter your choice (1-3): ");
        scanf(" %c", &choice);
        getchar();  // Consume newline

        switch (choice) {
            case '1':
                printf("Enter username: ");
                fgets(username, sizeof(username), stdin);
                username[strcspn(username, "\n")] = 0;  // Remove newline

                printf("Enter password: ");
                fgets(password, sizeof(password), stdin);
                password[strcspn(password, "\n")] = 0;  // Remove newline

                hashed_password = hash(password);
                save_password(username, hashed_password);
                printf("Password saved successfully!\n");
                break;

            case '2':
                printf("Enter username: ");
                fgets(username, sizeof(username), stdin);
                username[strcspn(username, "\n")] = 0;  // Remove newline

                hashed_password = get_password(username);
                if (hashed_password != 0) {
                    printf("Hashed password for %s: %lu\n", username, hashed_password);
                } else {
                    printf("Username not found.\n");
                }
                break;

            case '3':
                printf("Exiting ...\n");
                return 0;

            default:
                printf("Invalid choice. Please try again.\n");
        }
    }

    return 0;
}