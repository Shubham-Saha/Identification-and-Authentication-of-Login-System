/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -std=gnu99 -Wall -g -o mylogin login_linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
/* Uncomment next line in step 2 */
#include "pwent.h"

#include<time.h>
#include <stdbool.h>

#define TRUE 1
#define FALSE 0
#define LENGTH 16

void sighandler() {

	/* add signalhandling routines here */
	/* see 'man 2 signal' */

	    // Ignore Ctrl-C (SIGINT)
    signal(SIGINT, SIG_IGN);

    // Ignore Ctrl-\ (SIGQUIT)
    signal(SIGQUIT, SIG_IGN);

    // Ignore Ctrl-Z (SIGTSTP)
    signal(SIGTSTP, SIG_IGN);
}

char *generate_salt() {
    static char salt[3]; // 2 characters + null terminator
    char valid_chars[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";

    // Seed the random number generator
    srand((unsigned int)time(NULL));

    // Generate two random characters from the valid_chars
    for (int i = 0; i < 2; ++i) {
        int randIndex = rand() % strlen(valid_chars); // Generate a random index
        salt[i] = valid_chars[randIndex]; // Assign a character at the random index
    }

    salt[2] = '\0'; // Null-terminate the string

	return salt;
}

int main(int argc, char *argv[]) {

	//struct passwd *passwddata; /* this has to be redefined in step 2 */
	/* see pwent.h */
	mypwent *passwddata;

	char important1[LENGTH] = "**IMPORTANT 1**";

	char user[LENGTH];

	char important2[LENGTH] = "**IMPORTANT 2**";

	char   *c_pass; //you might want to use this variable later...
	char prompt[] = "password: ";
	char *user_pass;

	char temp;
	char *new_pass;
	char* new_salt;
	int login_attempts = 5;
	int update_status;
	bool flag = false;

	sighandler();

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important1' before input of login name: %s\n",
				important1);
		printf("Value of variable 'important2' before input of login name: %s\n",
				important2);

		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

		//if (gets(user) == NULL) /* gets() is vulnerable to buffer */
			//exit(0); /*  overflow attacks.  */
		if(fgets(user, sizeof(user), stdin) == NULL)
			exit(0);
		user[strcspn(user, "\n")] = 0; // Remove newline character

		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important 1' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important1);
		printf("Value of variable 'important 2' after input of login name: %*.*s\n",
		 		LENGTH - 1, LENGTH - 1, important2);

		user_pass = getpass(prompt); //getpass function is traditionally used to read a password from stdin without echoing it to the console.
		passwddata = mygetpwnam(user); //gets the password record for the username entered.

		if (passwddata != NULL) {
			/* You have to encrypt user_pass for this to work */
			/* Don't forget to include the salt */
			c_pass = crypt(user_pass, passwddata->passwd_salt);

			if (!strcmp(c_pass, passwddata->passwd)) {

				printf(" You're in !\n");
				passwddata->pwage++;
				update_status = mysetpwent(user, passwddata);
							
				if (passwddata->pwage > 9){
					printf("You should immediatly change your password. Type 'C' for changing password: ");
					
					scanf("%c", &temp);

					if(temp == 'C' || temp == 'c'){
						new_pass = getpass(prompt);
						
						new_salt = generate_salt();
						passwddata->passwd_salt = new_salt;
						c_pass = crypt(new_pass, passwddata->passwd_salt);
						passwddata->passwd = c_pass;
						
						passwddata->pwage = 0;
						passwddata->pwfailed = 0;
						
						update_status = mysetpwent(user, passwddata);
						if(update_status == 0) {
							printf("Password changed successfully.\n");
						} 
						else {
							printf("Failed to change password.\n");
						}
					}
					else{
						printf("Wrong input.");
					}
				}
				/*  check UID, see setuid(2) */
				/*  start a shell, use execve(2) */

				// Set the UID to the authenticated user's UID
				if (setuid(passwddata->uid) == -1) {
					perror("setuid failed");
					exit(EXIT_FAILURE);
				}

				char *args[] = { "/bin/sh", NULL };
				execve("/bin/sh", args, NULL);

				// If execve returns, it failed
				perror("execve failed");
				exit(EXIT_FAILURE);
			}
			else{
				printf("Login Incorrect \n");
				passwddata->pwfailed++;
				if(passwddata->pwfailed > 4){
					printf("Maximum login attempt reached.\n");
					passwddata->pwfailed = 0;
					flag = true;
				}
				 else {
        			printf("You have %d attempts left\n", login_attempts - passwddata->pwfailed);
    			}
				update_status = mysetpwent(user, passwddata);
				if (update_status != 0) {
					perror("Failed to update user login attempts");
				}
				if (flag == true)
				{
					return 0;
				}
				
			}
		}
		else{
			printf("Null Database. \n");
			return 0;
		}
	}
	return 0;
}