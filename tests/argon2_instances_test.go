package tests

var katGood = []string{
	"$argon2i$m=120,t=5000,p=2",
	"$argon2i$m=120,t=4294967295,p=2",
	"$argon2i$m=2040,t=5000,p=255",
	"$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0",
	"$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0ZQ",
	"$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0ZQA",
	"$argon2i$m=120,t=5000,p=2,data=sRlHhRmKUGzdOmXn01XmXygd5Kc",
	"$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0,data=sRlHhRmKUGzdOmXn01XmXygd5Kc",
	"$argon2i$m=120,t=5000,p=2$/LtFjH5rVL8",
	"$argon2i$m=120,t=5000,p=2$4fXXG0spB92WPB1NitT8/OH0VKI",
	"$argon2i$m=120,t=5000,p=2$BwUgJHHQaynE+a4nZrYRzOllGSjjxuxNXxyNRUtI6Dlw/zlbt6PzOL8Onfqs6TcG",
	"$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0$4fXXG0spB92WPB1NitT8/OH0VKI",
	"$argon2i$m=120,t=5000,p=2,data=sRlHhRmKUGzdOmXn01XmXygd5Kc$4fXXG0spB92WPB1NitT8/OH0VKI",
	"$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0,data=sRlHhRmKUGzdOmXn01XmXygd5Kc$4fXXG0spB92WPB1NitT8/OH0VKI",
	"$argon2i$m=120,t=5000,p=2$4fXXG0spB92WPB1NitT8/OH0VKI$iPBVuORECm5biUsjq33hn9/7BKqy9aPWKhFfK2haEsM",
	"$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0$4fXXG0spB92WPB1NitT8/OH0VKI$iPBVuORECm5biUsjq33hn9/7BKqy9aPWKhFfK2haEsM",
	"$argon2i$m=120,t=5000,p=2,data=sRlHhRmKUGzdOmXn01XmXygd5Kc$4fXXG0spB92WPB1NitT8/OH0VKI$iPBVuORECm5biUsjq33hn9/7BKqy9aPWKhFfK2haEsM",
	"$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0,data=sRlHhRmKUGzdOmXn01XmXygd5Kc$4fXXG0spB92WPB1NitT8/OH0VKI$iPBVuORECm5biUsjq33hn9/7BKqy9aPWKhFfK2haEsM",
	"$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0,data=sRlHhRmKUGzdOmXn01XmXygd5Kc$iHSDPHzUhPzK7rCcJgOFfg$EkCWX6pSTqWruiR0",
	"$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0,data=sRlHhRmKUGzdOmXn01XmXygd5Kc$iHSDPHzUhPzK7rCcJgOFfg$J4moa2MM0/6uf3HbY2Tf5Fux8JIBTwIhmhxGRbsY14qhTltQt+Vw3b7tcJNEbk8ium8AQfZeD4tabCnNqfkD1g",
}

var katBad = []string{
	/* bad function name */
	"$argon2j$m=120,t=5000,p=2",

	/* missing parameter 'm' */
	"$argon2i$t=5000,p=2",

	/* missing parameter 't' */
	"$argon2i$m=120,p=2",

	/* missing parameter 'p' */
	"$argon2i$m=120,t=5000",

	/* value of 'm' is too small (lower than 8*p) */
	"$argon2i$m=15,t=5000,p=2",

	/* value of 't' is invalid */
	"$argon2i$m=120,t=0,p=2",

	/* value of 'p' is invalid (too small) */
	"$argon2i$m=120,t=5000,p=0",

	/* value of 'p' is invalid (too large) */
	"$argon2i$m=2000,t=5000,p=256",

	/* value of 'm' has non-minimal encoding */
	"$argon2i$m=0120,t=5000,p=2",

	/* value of 't' has non-minimal encoding */
	"$argon2i$m=120,t=05000,p=2",

	/* value of 'p' has non-minimal encoding */
	"$argon2i$m=120,t=5000,p=02",

	/* value of 't' exceeds 2^32-1 */
	"$argon2i$m=120,t=4294967296,p=2",

	/* invalid Base64 for keyid (length = 9 characters) */
	"$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0Z",

	/* invalid Base64 for keyid (unprocessed bits are not 0) */
	"$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0ZR",
	"$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0ZQB",

	/* invalid keyid (too large) */
	"$argon2i$m=120,t=5000,p=2,keyid=Mwmcv5/avkXJ",

	/* invalid associated data (too large) */
	"$argon2i$m=120,t=5000,p=2,data=Vrai0ME0m7lorfxfOCG3+6we5N89+2hXwkbv0C5SECab",

	/* invalid salt (too small) */
	"$argon2i$m=120,t=5000,p=2$+yPbRi6hdw",

	/* invalid salt (too large) */
	"$argon2i$m=120,t=5000,p=2$SIZzzPhYC/CXOf64vWG/IZjO/amlRgvKscaRCYwdg9R1boFN/NjaC1VdXdcOtFx+0A",

	/* invalid output (too small) */
	"$argon2i$m=120,t=5000,p=2$4fXXG0spB92WPB1NitT8/OH0VKI$iHSDPHzUhPzK7rCcJgOFfg$c+jbgTK0PT0eCMI",

	/* invalid output (too large) */
	"$argon2i$m=120,t=5000,p=2$4fXXG0spB92WPB1NitT8/OH0VKI$iHSDPHzUhPzK7rCcJgOFfg$KtTPhiUlDb98psIiNxUSZ8GYVEm1CsfEaLJrppBe5poD2/sQOUu5mmowSiQUbH+ZK3PjFdY3KUuf83bT5XqTZy0",
}
