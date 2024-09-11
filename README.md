# oauth2 sample

① First, start the oauth2-server-demo, and then start the oauth2-client-demo.

② Once both have started, visit http://localhost:8080.

③ If you are not logged in, you will be redirected to http://localhost:8080/login.

④ Click Go!, and you will be redirected to http://127.0.0.1:8000/login. At this page, you can enter the account credentials as follows:  
Username: test  
Password: abc123  
Remember me: Yes

⑤ After completing the process, you will be redirected to the authorization success page at http://localhost:8080/callback.

⑥ Close the browser and reopen it. Visit http://localhost:8080 again, click Go! and notice that you still need to enter your username and password? (bug)
Return to the previous page at http://localhost:8080, and click Go! again. This time, the authorization will be successful.

