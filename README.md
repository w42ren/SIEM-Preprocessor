Create the auth logfile auth_synthetic.log
Run the data analysis script
python ssh_auth_agg_api_db.py --assets-db cmdb.sqlite --input auth_synthetic.log  --out ssh_failed_agg.jsonl  --api-url http://localhost:8080/v1/ssh-failures --api-token mysecrettoken123                                                   
