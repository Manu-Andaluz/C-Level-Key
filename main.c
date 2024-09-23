#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FILENAME "passwords.txt"
#define MAX_LINE 256
#define MASTER_FILE "master.txt"

// Function Prototypes
void set_master_password();
void add_new_password();
void get_existing_password();

// Function pointer
typedef void (*MenuFunction)();
typedef struct
{
    char option;
    const char *description;
    MenuFunction function;
} MenuOption;

typedef struct
{
    char *username;
    char *enctrypted_password;
} PasswordEntry;

char global_master_password[MAX_LINE] = {0};

// Simple hash function
unsigned long hash(char *str)
{                              // We define the return value beofre we start the function
    unsigned long hash = 5381; // We start with a hash value of 5381
    int c;                     // We define a variable to store each character

    while ((c = *str++))                 // We loop through each character of the string ( we point to the address memory of the string with *str and then move to the next character with ++)
        hash = ((hash << 5) + hash) + c; // We do something like hash = (hash * 32) + hash + c, ( 32 is 2^5, then we add the hash to the result and then add the character)

    return hash;
}

void encrypt_decrypt(char *data, char *key)
{
    int data_len = strlen(data);
    int key_len = strlen(key);
    for (int i = 0; i < data_len; i++)
    {
        data[i] = data[i] ^ key[i % key_len];
    }
}

PasswordEntry *create_password_entry(const char *username, const char *password)
{
    PasswordEntry *entry = (PasswordEntry *)malloc(sizeof(PasswordEntry));
    if (entry == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    entry->username = strdup(username);
    entry->enctrypted_password = strdup(password);

    return entry;
}

void free_password_entry(PasswordEntry *entry)
{
    if (entry)
    {
        free(entry->username);
        free(entry->enctrypted_password);
        free(entry);
    }
}

int verify_master_password(char *master_password)
{
    if (master_password[0] == '\0')
    {
        printf("Please introduce a master password first.\n");
        return 0;
    }

    FILE *file = fopen(MASTER_FILE, "r");
    if (file == NULL)
    {
        printf("No master password set. Please set a master password first.\n");
        return 0;
    }

    unsigned long stored_hash;
    fscanf(file, "%lu", &stored_hash);
    fclose(file);

    if (hash(global_master_password) != stored_hash)
    {
        while (1)
        {
            printf("Incorrect master password!\n");
            char temp_master_password[MAX_LINE];
            fgets(temp_master_password, sizeof(temp_master_password), stdin);
            temp_master_password[strcspn(temp_master_password, "\n")] = 0;

            if (hash(temp_master_password) == stored_hash)
            {
                strcpy(global_master_password, temp_master_password);
                return 1;
            }
        }
    }
}

void set_master_password()
{
    char master_password[MAX_LINE];
    printf("Enter new master password: ");
    fgets(master_password, sizeof(master_password), stdin);
    master_password[strcspn(master_password, "\n")] = 0;

    FILE *file = fopen(MASTER_FILE, "w");
    if (file == NULL)
    {
        printf("Error creating master password file!\n");
        return;
    }

    fprintf(file, "%lu", hash(master_password));
    fclose(file);

    strcpy(global_master_password, master_password);

    printf("Master password set successfully!\n");
}

void save_password(PasswordEntry *entry)
{
    encrypt_decrypt(entry->enctrypted_password, global_master_password);

    FILE *file = fopen(FILENAME, "a");
    if (file == NULL)
    {
        printf("Error opening file!\n");
        return;
    }

    // Convert encrypted password to hexadecimal string
    char hex_password[MAX_LINE * 2 + 1]; // Each byte becomes two hex characters
    int len = strlen(entry->enctrypted_password);
    for (int i = 0; i < len; i++)
    {
        sprintf(hex_password + (i * 2), "%02x", (unsigned char)entry->enctrypted_password[i]);
    }

    fprintf(file, "%s:%s\n", entry->username, hex_password);

    fclose(file);
}

PasswordEntry *get_password(char *username, char *master_password)
{
    FILE *file = fopen(FILENAME, "r");
    if (file == NULL)
    {
        printf("Error opening file!\n");
        return NULL;
    }

    char line[MAX_LINE];
    char stored_username[MAX_LINE];
    char encrypted_password[MAX_LINE];

    while (fgets(line, sizeof(line), file))
    {
        char *colon = strchr(line, ':');
        if (colon == NULL)
            continue;

        *colon = '\0';
        strcpy(stored_username, line);
        strcpy(encrypted_password, colon + 1);
        encrypted_password[strcspn(encrypted_password, "\n")] = 0;

        if (strcmp(username, stored_username) == 0)
        {
            fclose(file);

            // Convert hexadecimal string back to bytes
            int len = strlen(encrypted_password) / 2;
            char *decrypted_password = (char *)malloc(len + 1);
            for (int i = 0; i < len; i++)
            {
                sscanf(encrypted_password + (i * 2), "%2hhx", (unsigned char *)&decrypted_password[i]);
            }
            decrypted_password[len] = '\0';

            // && - || are logical operators, & - | are bitwise operators
            if (master_password != NULL && master_password[0] != 0)
            {
                encrypt_decrypt(decrypted_password, master_password);
            }
            else
            {
                printf("No master password set. Please set a master password first.\n");
            }

            PasswordEntry *entry = create_password_entry(username, decrypted_password);
            free(decrypted_password);
            return entry;
        }
    }

    fclose(file);
    return NULL;
}

// strcpy in vulnerable_function doesn't check buffer size, potentially causing overflow. strncpy in safe_function prevents this by limiting the copy operation to the buffer's size.
// The sizeof(buffer) - 1 ensures we leave space for the null terminator, The -1 is crucial because C strings need a null terminator, and we're manually adding it.

// New function to learn buffer overflow
void vulnerable_function(char *input)
{
    char buffer[10];
    // This is vulnerable to buffer overflow
    strcpy(buffer, input);
    printf("Buffer: %s\n", buffer);
}

// New function to demostrate sage input handling
void safe_function(char *input)
{
    char buffer[10];
    // This prevents buffer overflow
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    printf("Buffer: %s\n", buffer);
}

void get_existing_password()
{

    char username[MAX_LINE];
    char password[MAX_LINE];

    if (global_master_password[0] == 0)
    {
        printf("Enter master password: ");
        fgets(global_master_password, sizeof(global_master_password), stdin);
        global_master_password[strcspn(global_master_password, "\n")] = 0;

        if (!verify_master_password(global_master_password))
        {
            printf("Incorrect master password!\n");
            return;
        }
    }

    printf("Enter username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0;

    printf("Get existing password\n");

    PasswordEntry *retrieved_entry = get_password(username, global_master_password);
    if (retrieved_entry)
    {
        printf("Password for %s: ", username);
        printf("%s\n", retrieved_entry->enctrypted_password);
        free_password_entry(retrieved_entry);
    }
    else
    {
        printf("Username not found.\n");
    }
}

void add_new_password()
{

    char username[MAX_LINE];
    char password[MAX_LINE];

    if (global_master_password[0] == 0)
    {
        printf("Enter master password: ");
        fgets(global_master_password, sizeof(global_master_password), stdin);
        global_master_password[strcspn(global_master_password, "\n")] = 0;

        if (!verify_master_password(global_master_password))
        {
            printf("Incorrect master password!\n");
            return;
        }
    }

    printf("Enter username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0;

    printf("Enter password: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = 0;

    PasswordEntry *entry = create_password_entry(username, password);
    if (entry)
    {
        save_password(entry);
        printf("Password saved successfully!\n");
        free_password_entry(entry);
    }
    else
    {
        printf("Failed to save password.\n");
    }
}

int main()
{
    // In C, when you use a function name without parentheses, it automatically decays into a pointer to that function.
    // This is similar to how array names decay into pointers to their first elements.
    MenuOption menu[] = {
        {'1', "Set master password", set_master_password},     // automatically treated as pointers, the same as &set_master_password
        {'2', "Add new password", add_new_password},           // automatically treated as pointers, the same as &add_new_password
        {'3', "Get existing password", get_existing_password}, // automatically treated as pointers, the same as &get_existing_password
        {'4', "Exit", NULL}};
    // void (*func_ptr)() = set_master_password;  // This is valid
    // func_ptr();  // This calls the function
    // (*func_ptr)();  // This is equivalent and also calls the function


    // Calculate the number of options in the menu array
    // sizeof(menu) gives the total size of the array in bytes
    // sizeof(menu[0]) gives the size of a single element in bytes
    // sizeof(menu) would be 64 (4 * 16)
    // sizeof(menu[0]) would be 16
    // 64 / 16 = 4 elements
    int num_options = sizeof(menu) / sizeof(menu[0]);

    char choice;
    while (1)
    {
        printf("\nPassword Manager\n");
        for (int i = 0; i < num_options; i++)
        {
            printf("%c. %s\n", menu[i].option, menu[i].description);
        }
        printf("Enter your choice: ");
        choice = getchar();
        getchar(); // Consume newline

        for (int i = 0; i < num_options; i++)
        {
            if (choice == menu[i].option)
            {
                menu[i].function();
                break;
            }
        }
    }

    return 0;
}
