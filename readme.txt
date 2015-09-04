#Programming Challenge - Log Monitoring 

Approach Used:

We created regex for various common attack types like sql injection , xss,csrf,local file inclusion		
,directory traversal etc. and stored them in filters.txt along with a number (0-7) denoting severity of attack.

The requests that tested positive against these regex were classified as vulnerable and written to "vulnerable.txt" and those which failed against these tests were put into "nonv.txt"

Now after this basic filtering we clustered the requests in vulnerable.txt based on the attack types (Lets call this group xssv) and found there baseurl or path.

	 for eg. /abc/xyz?id=32&ds=56 whould be stripped to /abc/xyz
Then the requests from "nonv.txt" which contained the same baseurl or path were grouped and there avg bytes sent were calculated (lets call this number avg_byte). 
Now the bytes sent of requests from group xssv were compared with avg_byte. Any request which deviated more then 100 bytes was considered to be more risky.

The final list to vulnerable requests is printed

Note: We chose 100 bytes for the sake of convinience ideally it should be done using standard deviation and normalistaion.

