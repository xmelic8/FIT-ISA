//------------------------------------------------------------------------------
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <openssl/md5.h>
#include <signal.h>
#include <getopt.h>
#include <linux/if_link.h>
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*Textovy retezec s napovedou.*/
const char *HELP =
  "Program: Klient SIP\n\n"
  "Autor:   Michal Melichar(c) 2015\n\n"
  "Popis:   Klient protokolu SIP 2.0, ktery se dokaze pripojit k serveru a \n"
  "         autentizovat se pomoci mechanismu MD5 digest.\n\n"
  "Pouziti: sipklient -h                Vytiskne napovedu k pouziti programu.\n\n"
  "         sipklient -p profile.txt    Spusteni programu. Parametr p je povinny.\n"
  "                   -m messages.txt   Parametr m je volitelny. Soubor je seznam\n"
  "                                     prijemcu a zprav.\n\n"
  "Povinny obsah souboru profile.txt:\n"
  "         server=SERVER - jmeno/IP adresa serveru, na ktery se pripojujeme\n"
  "         username=USERNAME - uzivatelske jmeno SIP uctu\n"
  "         password=PASSWORD - heslo k uctu\n"
  "         expires=EXPIRES - doba vyprseni autentizace v sekundach\n\n"
  "Povinny obsah souboru messages.txt:\n"
  "         Soubor ma dva sloupce oddelene mezerou. Prvni sloupec obsahuje adresu\n"
  "         prijemce a druhy sloupec obsahuje zpravu, ktera je odeslana prijemci.\n"
  "         Priklad: bob@192.168.0.60 Hello,Bob!\n"
  "----------------------------------------------------------------------------\n";
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
#define MAX_BUFFER 50
#define MAX_BUFFER_2 100
#define MAX_BUFFER_3 500
#define MAX_BUFFER_ZPRAVA 5000
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*Jednotlive chyby, krere mohou v prubehu programu nastat.*/
enum {
  E_PARAMETR,
  E_MEMORY,
  E_OPEN_FILE,
  E_CLOSE_FILE,
  E_READ_FILE,
	E_MAX_BUFFER,
	E_ZPRAVA,
	E_ODPOVED_SERVER,
	E_TYP_ODPOVED,
	E_BIND,
	E_METOD,
	E_SERVER,
	E_USER,
	E_PASSWORD,
	E_PORT,
	E_MOJE_IP,
	E_PRIHLASENI,
	E_SOCKET,
};
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// Jednotliva chybova hlaseni, ktera se vazou k vyse uvedenemu vyuctovemu typu.
const char *ERROR[] = {
  "ERROR: Spatne zadane parametry programu.",
  "ERROR: Doslo k chybe pri alokaci pameti.",
  "ERROR: Soubor se nepodarilo otevrit.",
  "ERROR: Soubor se nepodarilo koretkne uzavrit.",
  "ERROR: Doslo k chybe pri zpracovani souboru.",
	"ERROR: Doslo k vnitrni chybe programu.",
	"ERROR: Pripojeni k SIP serveru se nezdarilo.",
	"ERROR: Doslo k chybe na strane serveru. Program nenalezl odpoved serveru.",
	"ERROR: Server odeslal spatny typ odpovedi.",
	"ERROR: Doslo k chybe pri vazbe socketu na lokalni port.",
	"ERROR: SIP server neprijal vas pozadavek.",
	"ERROR: V souboru profiles.txt je spatne zadan server.",
	"ERROR: V souboru profiles.txt je spatne zadane jmeno uzivatele.",
	"ERROR: V souboru profiles.txt je spatne zadane heslo uzivatele.",
	"ERROR: Spatne cislo portu nebo je port spatne zadan.",
	"ERROR: Doslo k chybe pri urcovani aktualni IP adresy, na ktere bezi klient."
	"ERROR: Doslo k chybe pri pokusu o prihlaseni.",
	"ERROR: Doslo k problemu s odesilanim socketu.",
};
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/* Globalni promenne, jejiz hodnota je vyuzivana vramci rozhodovani programu ve 
   vice funkcich.*/
bool alarm_zapnut = false;
bool pozadovane_odhlaseni = false;
bool pocet_zprav = false;

//Globalni ukazatele pro dynamickou alokaci pameti
char *soubor_profilu = NULL;// Promenna pro ulozeni nazvu souboru s profilem
char *soubor_zpravy = NULL;// Promenna pro ulozeni nazvu souboru se zpravama

bool local_host = false;// Promenna pro nastaveni zda byl zadan localhost jako adresa serveru

bool prihlaseni_pokus = false;
bool prihlaseni_ok = false;
bool odhlaseni_ok = false;
bool prihlaseni_nezdarilo = false;
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// Struktura obsahujici informace pro sestaveni zpravy odeslane na server
typedef struct {
  	char user[MAX_BUFFER_3];
  	char password[MAX_BUFFER_3];
	char tag[MAX_BUFFER];
	char call_id[MAX_BUFFER];
	char branch[MAX_BUFFER_2];
	char realm[MAX_BUFFER_2];
	char nonce[MAX_BUFFER_2];
	char *moje_ip;
	unsigned int muj_port;
	char muj_port_char[6];
	unsigned int port_server;
	char port_server_char[6];
	char cilova_ip[MAX_BUFFER_3];
	bool odpoved;
	unsigned int cseq;
	unsigned long int expires;
	char metoda[9];
}Tzprava;

// Struktura obsahujici buffery pro prijem a odeslani zpravy
typedef struct {
	char zaslana_zprava[MAX_BUFFER_ZPRAVA];
	char prijata_zprava[MAX_BUFFER_ZPRAVA];
	int typ_odpovedi;
	char nazev_odpovedi[MAX_BUFFER_2];
}Tbuf_zprava;

//Struktura obsahujici promenne pro vypocet MD5 algoritmu
typedef struct{
	char ha_1[33];
	char ha_2[33];
	char md5[33];
}Tmd5;

//Struktura obsahujici odesilanou zpravu a adresata zpravy
typedef struct {
  char zprava[MAX_BUFFER_ZPRAVA];
  char adresa[MAX_BUFFER_3];
	unsigned int adresa_port;
	char adresa_port_char[6];
	char tag[MAX_BUFFER];
	char call_id[MAX_BUFFER];
	char branch[MAX_BUFFER_2];
}Todeslana_zprava;

//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
//Deklarace funkci
void vytvor_zpravu(Tzprava *matice, Tbuf_zprava *buffer, Tmd5 *md5_zprava, Todeslana_zprava *message, int rozhodovani);
void ziskej_udaje(char hledany_vyraz[], Tzprava *matice, Tbuf_zprava *buffer, bool nonce);
void printfERR(int error);
void vytvor_md5(Tzprava *matice, Tmd5 *md5_zprava);
void generuj_hodnoty(Tzprava *matice, Todeslana_zprava *message, int i);
void cislo_odpovedi(Tbuf_zprava *buffer);
void vypis_odpovedi(Tzprava *matice, int typ_tisku, Tbuf_zprava *buffer, Todeslana_zprava *message);
void zpracuj_signal(int cislo_signalu);
void nastav_vychozi_hodnoty(Tzprava *matice, Todeslana_zprava *message);

bool ziskat_udaje(char hled_vyraz[], char vstup[], char vystup_tmp[]);
int zpracuj_soubor(char *soubor, Tzprava *matice);
void uvolni_pamet();
void zpracuj_port(char ip_adresa[], char port[]);
void zjisti_moji_ip(char *moje_ip);
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// Telo hlavni funkce programu
int main(int argc, char * argv[])
{
    int socket_server;//Promenna pro ulozeni vytvoreneho socketu
	/*Promenne k ulozeni potrebnych informaci k sestaveni socketu. Server = struktura
	obsahujici informace ke spojeni. Servaddr = vyuzivana pro funkci bind() a prirazeni
	socketu konkretni cislo socketu, z ktereho odesilame sockety. */
    struct sockaddr_in server, servaddr;
	socklen_t len;//Velikost adresove strukturz pro funkci recvform()
    unsigned int navratovy_kod;//Navratovy kod funkce recvform()
	Tzprava zprava_sip;
	Tbuf_zprava buffer_zpravy;
	Tmd5 md5_zprava;
	Todeslana_zprava message;

	//Promenne pro urceni ruznych stavu behem behu programu
	/*bool prihlaseni_pokus = false;
	bool prihlaseni_ok = false;
	bool odhlaseni_ok = false;
	bool prihlaseni_nezdarilo = false;*/
	int timeout_500 = 32;/* Doba v sekundach pro nastaveni cekani, nez program 
	odesle dalsi pozadavek o registraci na server. V pripade, ze server odpovedel 
	hodnout 500.*/

	int opt;// Promenna pro pouziti funkce getopt
 	char *optstring = "hp:m:";//retezec obsahujici definici prepinacu
 	opterr = 0;// Nastaveni potlaceni chybove zpravy funkce getopt()
	FILE *soubor_messages = NULL;
 	bool param_p = false;//Zda byl zadany parametr p
	bool param_m = false;//Zda byl zadany parametr m
 	int navratova_hodnota = 0;

	char *ukazatel = NULL;//Ukazatel na prvek v souboru messages.txt
 	char *ukazatel2 = NULL;//Ukazatel na prvek v souboru messages.txt
 	char tmp_pole[MAX_BUFFER_3];
 	int pocet = 0;//Promenna pro zjisteni delky retezce, kvuli alokaci pole
	
	int pocet_opakovani = 0;
	int pocet_opakovani2 = 0;

	signal(SIGUSR1, zpracuj_signal);

//Zpracovani parametru programu
  while ((opt = getopt(argc, argv, optstring)) != -1) {
    switch (opt){
      case 'h'://Pro napovedu
        if(argc == 2){
          printf("%s", HELP);
          return 0;
        }
        else{
          printfERR(E_PARAMETR);
			raise(SIGUSR1);
        }
      case 'p':
        /* Dynamicka alokace pole pro retezec obsahujici nazev souboru. Osetreni
         * chyby pri alokaci pameti. Ulozeni retezce a argumentu programu do
         * promenne.                                                          */
        if((soubor_profilu = (char *) malloc(strlen(optarg) + 1)) == NULL){
          printfERR(E_MEMORY);
			raise(SIGUSR1);
		}
        strcpy(soubor_profilu, optarg);
        param_p = true;
        break;
      case 'm':
		param_m = true;
		pocet_zprav = true;
        if((soubor_zpravy = (char *) malloc(strlen(optarg) + 1)) == NULL){
          printfERR(E_MEMORY);
			raise(SIGUSR1);
		}
        strcpy(soubor_zpravy, optarg);
        break;
      default:
        printfERR(E_PARAMETR);
		raise(SIGUSR1);
    }
  }

  // V pripade, ze nebyl zadany povinny parametr -p soubor.
  if(param_p == false){
    printfERR(E_PARAMETR);
	raise(SIGUSR1);
  }

  navratova_hodnota = zpracuj_soubor(soubor_profilu, &zprava_sip);
  switch(navratova_hodnota){
    case 1:
      printfERR(E_CLOSE_FILE);
		raise(SIGUSR1);
      break;
    case 2:
      printfERR(E_READ_FILE);
		raise(SIGUSR1);
      break;
  }

	if(((soubor_messages = fopen(soubor_zpravy, "r")) == NULL) && (param_m == true)){
		param_m = false;
		printfERR(E_READ_FILE);
	}


	nastav_vychozi_hodnoty(&zprava_sip, &message);//Nastaveni vychozich hodnost struktur	

	// Vytvoreni UDP socketu
    socket_server = socket(PF_INET, SOCK_DGRAM, 0);

	/* Nastaveni socketu, z ktereho budeme odesilat pozadavky na server. 
	   Nastaveni socketu pro IP a PORT pro spojeni se SIP serverem.*/
	memset(&server, 0, sizeof(server));
    server.sin_family = PF_INET;
	struct hostent *hosten;
	hosten = gethostbyname(zprava_sip.cilova_ip);
	bcopy((char *)hosten->h_addr_list[0], (char *)&server.sin_addr.s_addr, hosten->h_length);
	server.sin_port = htons(zprava_sip.port_server);
	
	/* Nastaveni socketu, z ktereho budeme odesilat pozadavky na server. 
	   Nastaveni propojeni IP adresy s odchozim portem.*/
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = PF_INET;

	//Nastaveni adresy localhost, pokud server bezi na stejne adrese
	if(((strcmp(zprava_sip.cilova_ip, "localhost")) == 0) || ((strcmp(zprava_sip.cilova_ip, "127.0.0.1")) == 0)){
		servaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		zprava_sip.moje_ip = inet_ntoa(servaddr.sin_addr);//Ziskani me adresy
	}
	else{//Pokud IP serveru a IP klienta je odlisna, tak se zjisti a nastavi adresa klienta
		zprava_sip.moje_ip = (char *) malloc(sizeof(char) * 16);
		zjisti_moji_ip(zprava_sip.moje_ip);
		struct hostent *hosten2;
		hosten2 = gethostbyname(zprava_sip.moje_ip);
		bcopy((char *)hosten2->h_addr_list[0], (char *)&servaddr.sin_addr.s_addr, hosten2->h_length);
	}

	servaddr.sin_port = htons(zprava_sip.muj_port);
	len = sizeof(servaddr);

	// Generovani tagu
	generuj_hodnoty(&zprava_sip, NULL, 1);

	// Prirazeni konkretniho portu k adrese. 
	if(bind(socket_server, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0){
		printfERR(E_BIND);
		raise(SIGUSR1);
	}

	// Nastaveni signalu na odchytavani
	signal(SIGTERM, zpracuj_signal);
	signal(SIGQUIT, zpracuj_signal);
	signal(SIGINT, zpracuj_signal);

	/* Nekonecny cyklus starajici se o odeslani zpravy, udrzovani spojeni a 
	   v pripade potreby reakce na ochytnuty signal.*/
	while(1){	
		memset(buffer_zpravy.zaslana_zprava, 0, MAX_BUFFER_ZPRAVA);
		if(((prihlaseni_ok == true) && (pocet_zprav != false) && (param_m == true)) ||((prihlaseni_nezdarilo == true) && (pocet_zprav != false))){
			memset(tmp_pole, 0, MAX_BUFFER_3);
			while(fgets(tmp_pole, sizeof(tmp_pole), soubor_messages)){
    			//Zpracovani adresata
    			ukazatel = strchr(tmp_pole, ' ');//Nastaveni ukazatele na konec adresata
    			pocet = ukazatel-tmp_pole;// Vypocet poctu delky adresata

				memset(message.adresa, 0, MAX_BUFFER_3);
    			strncpy(message.adresa, tmp_pole, pocet);//Zkopirovani adresata
				zpracuj_port(message.adresa, message.adresa_port_char);
				message.adresa_port = atoi(message.adresa_port_char);
				// Osetreni v pripade, ze bylo zadane moc vysoke cislo portu
				if(message.adresa_port > 65535){
					printfERR(E_PORT);
					raise(SIGUSR1);
				}
				
   				//Zpracovani zpravy
   				ukazatel2 = strchr(tmp_pole, '\n');//nastaveni ukazatele na konec radku
   				ukazatel++;//Posunuti ukazatele na zacatek zpravy
   				pocet = ukazatel2-ukazatel;//Vypocet delky zpravy+

				memset(message.zprava, 0, MAX_BUFFER_ZPRAVA);
   				strncpy(message.zprava, ukazatel, pocet);//Zkopirovani zpravy
	
				zprava_sip.cseq++;
				generuj_hodnoty(NULL, &message, 2);
				strcpy(zprava_sip.metoda, "MESSAGE");
				vytvor_zpravu(&zprava_sip, &buffer_zpravy, &md5_zprava, &message, 2);
				
				OPAKUJ:
					sendto(socket_server, &buffer_zpravy.zaslana_zprava, sizeof(buffer_zpravy.zaslana_zprava), MSG_DONTWAIT, (struct sockaddr *)&server, sizeof(server));		
					sleep(1);// Cekani programu, nez prijme odpoved
					// Cteni dat odeslanych dat serverem.
    				navratovy_kod = recvfrom(socket_server, &buffer_zpravy.prijata_zprava, sizeof(buffer_zpravy.prijata_zprava), MSG_DONTWAIT, (struct sockaddr *) &servaddr, &len);
					if((navratovy_kod == (-1)) || (navratovy_kod == 0)){
						/*Pokud klient neprijme odpoved od serveru, pokusi se vytvorenou 
					  	  zpravu poslast znovu jeste 2x. Pokud do te doby neprijme odpoved,
					  	  klient vypise chybu a program se ukonci.*/
						if(pocet_opakovani2 <= 2){
							pocet_opakovani2++;
							sleep(2);
							goto OPAKUJ;
						}
						else			
							printfERR(E_ZPRAVA);
					}
	
					cislo_odpovedi(&buffer_zpravy);
					if(buffer_zpravy.typ_odpovedi == 404){
						vypis_odpovedi(&zprava_sip, 3, &buffer_zpravy, &message);
							vypis_odpovedi(&zprava_sip, 2, &buffer_zpravy, &message);
						continue;
					}
					if(buffer_zpravy.typ_odpovedi != 202)
						if(pocet_opakovani < 2){
							pocet_opakovani++;
							vypis_odpovedi(&zprava_sip, 3, &buffer_zpravy, &message);
							vypis_odpovedi(&zprava_sip, 2, &buffer_zpravy, &message);
							goto OPAKUJ;
					}

				pocet_opakovani = 0;
				pocet_opakovani2 = 0;
				vypis_odpovedi(&zprava_sip, 3, &buffer_zpravy, &message);
				vypis_odpovedi(&zprava_sip, 2, &buffer_zpravy, &message);
			}

			pocet_zprav = false;			
		}

		if(prihlaseni_nezdarilo == true)
			exit(1);

		if((pozadovane_odhlaseni == true) && (prihlaseni_ok == true)){
			zprava_sip.expires = 0;
			alarm_zapnut = false;
			prihlaseni_ok = false;
		}

		//Vytvoreni zpravy podle zadanych parameteru
		if(alarm_zapnut == false){
			zprava_sip.cseq++;
			strcpy(zprava_sip.metoda, "REGISTER");
			
			if((zprava_sip.expires == 0) || (prihlaseni_pokus == true))
				vytvor_zpravu(&zprava_sip, &buffer_zpravy, &md5_zprava, NULL, 1);
			else
				vytvor_zpravu(&zprava_sip, &buffer_zpravy, &md5_zprava, NULL, 0);

			OPAKUJ_ODESLANI:
				// Odeslani socketu na danou IP adresu
				if(sendto(socket_server, &buffer_zpravy.zaslana_zprava, sizeof(buffer_zpravy.zaslana_zprava), MSG_DONTWAIT, (struct sockaddr *)&server, sizeof(server)) == -1){
					printf("%d %s %s@%s", zprava_sip.cseq, zprava_sip.metoda, zprava_sip.user, zprava_sip.moje_ip);
					if(zprava_sip.muj_port != 5060)
						printf(":%s", zprava_sip.muj_port_char);
					printf(" %s", zprava_sip.cilova_ip);
					if(zprava_sip.port_server != 5060)
						printf(":%s ", zprava_sip.port_server_char);
					printfERR(E_SOCKET);
					raise(SIGUSR1);
				}	
				sleep(1);// Cekani programu, nez prijme odpoved
			// Cteni dat odeslanych dat serverem.
			OPAKUJ_CTENI:
				memset(buffer_zpravy.prijata_zprava, 0, MAX_BUFFER_ZPRAVA);
    			navratovy_kod = recvfrom(socket_server, &buffer_zpravy.prijata_zprava, sizeof(buffer_zpravy.prijata_zprava), MSG_DONTWAIT, (struct sockaddr *) &servaddr, &len);
				if((navratovy_kod == (-1)) || (navratovy_kod == 0)){
					/*Pokud klient neprijme odpoved od serveru, pokusi se vytvorenou 
					  zpravu poslast znovu jeste 2x. Pokud do te doby neprijme odpoved,
					  klient vypise chybu a program se ukonci.*/
					if(pocet_opakovani2 <= 2){
						pocet_opakovani2++;
						sleep(2);
						goto OPAKUJ_ODESLANI;
					}	
					else		
						printfERR(E_ZPRAVA);
			}

			pocet_opakovani2 = 0;
			// Vypis pozadavku na server a nasledne vypis odpovedi serveru v danem formatu
			if(zprava_sip.expires == 0)
				vypis_odpovedi(&zprava_sip, 4, &buffer_zpravy, &message);
			else
				vypis_odpovedi(&zprava_sip, 1, &buffer_zpravy, &message);
			cislo_odpovedi(&buffer_zpravy);
			vypis_odpovedi(&zprava_sip, 2, &buffer_zpravy, &message);
			
			
			// Zpracovani odpovedi od serveru a vytvoreni nove zpravy
			switch(buffer_zpravy.typ_odpovedi){
				case 401:
					if(prihlaseni_pokus == true){
						prihlaseni_nezdarilo = true;
						printfERR(E_PRIHLASENI);
						break;
					}
					ziskej_udaje("nonce=", &zprava_sip, &buffer_zpravy, true);
					ziskej_udaje("realm=", &zprava_sip, &buffer_zpravy, false);

					vytvor_md5(&zprava_sip, &md5_zprava);
					memset(buffer_zpravy.zaslana_zprava, 0, MAX_BUFFER_ZPRAVA);
					memset(buffer_zpravy.prijata_zprava, 0, MAX_BUFFER_ZPRAVA);

					prihlaseni_pokus = true;
					break;

				case 200:
					prihlaseni_pokus = false;
					prihlaseni_ok = true;
					alarm_zapnut = true;
					/* Inicializace signalu alarm, slouzici k nastaveni upozorneni
					   na potrebu odeslat znovu registraci, kvuli uplynuti doby
					   expires.*/
					signal(SIGALRM, zpracuj_signal);
					if(zprava_sip.expires < 60)
						zprava_sip.expires = 60;
					
					alarm(zprava_sip.expires - 4);
					if(pozadovane_odhlaseni == true)
						odhlaseni_ok = true;
					break;
				
				case 403:
					printfERR(E_METOD);
					prihlaseni_nezdarilo = true;
					break;

				case 100:
					sleep(2);
					goto OPAKUJ_CTENI;

				case 500:
					printf("Doslo k vnitrni chybe(500) serveru. Klient se pokusi znovu navazat spojeni.\n");
					alarm_zapnut = true;
					signal(SIGALRM, zpracuj_signal);
					alarm(timeout_500);
					break;
				default:
					sleep(3);
					break;

			}
			// V pripade odhlaseni ze serveru
			if(odhlaseni_ok == true)
				break;
		}
	}

	// Zavreni socketu
	close(socket_server);

	// Uvolneni alokovane pameti.
  	free(soubor_profilu);
	free(soubor_zpravy);
	soubor_profilu = NULL;
	soubor_zpravy = NULL;

    return 0;
}

//Funkce pro zkompletovani zpravy zaslane na server
void vytvor_zpravu(Tzprava *matice, Tbuf_zprava *buffer, Tmd5 *md5_zprava, Todeslana_zprava *message, int rozhodovani){
	char cseq[4];//Pomocne pole k prevodu hodnoty cseq na retezec
	char expires[11];//Pomocne pole k prevodu hodnoty expires na retezec
	char content[6];

	sprintf(cseq, "%d", matice->cseq);// Prevod ciselne hodnoty na retezec
	sprintf(expires, "%lu", matice->expires);// Prevod ciselne hodnoty na retezec
	if(rozhodovani == 2)
		sprintf(content, "%d", strlen(message->zprava));

	//Slozeni vysledne zpravy zaslane serveru
	strcpy(buffer->zaslana_zprava, matice->metoda);
	strcat(buffer->zaslana_zprava, " sip:");
	if(rozhodovani == 2)
		strcat(buffer->zaslana_zprava, message->adresa);
	else
		strcat(buffer->zaslana_zprava, matice->cilova_ip);
	strcat(buffer->zaslana_zprava, " SIP/2.0\r\nVia: SIP/2.0/UDP ");
	strcat(buffer->zaslana_zprava,matice->moje_ip);
	strcat(buffer->zaslana_zprava, ":");
	strcat(buffer->zaslana_zprava, matice->muj_port_char);
	strcat(buffer->zaslana_zprava, ";");
	//strcat(buffer->zaslana_zprava, ":32866;");
	if(rozhodovani == 2)
		strcat(buffer->zaslana_zprava,message->branch);
	else
		strcat(buffer->zaslana_zprava,matice->branch);
	strcat(buffer->zaslana_zprava, ";rport\r\n");
	if(rozhodovani != 2){
		strcat(buffer->zaslana_zprava, "Contact: <sip:");
		strcat(buffer->zaslana_zprava, matice->user);
		strcat(buffer->zaslana_zprava, "@");
		strcat(buffer->zaslana_zprava,matice->moje_ip);
		strcat(buffer->zaslana_zprava, ":");
		strcat(buffer->zaslana_zprava, matice->muj_port_char);
		strcat(buffer->zaslana_zprava, ">\r\n");
	}
	strcat(buffer->zaslana_zprava, "From: <sip:");
	strcat(buffer->zaslana_zprava, matice->user);
	strcat(buffer->zaslana_zprava, "@");
	strcat(buffer->zaslana_zprava, matice->cilova_ip);
	strcat(buffer->zaslana_zprava, ">");
	strcat(buffer->zaslana_zprava, ";");
	if(rozhodovani == 2)
		strcat(buffer->zaslana_zprava, message->tag);
	else
		strcat(buffer->zaslana_zprava, matice->tag);
	strcat(buffer->zaslana_zprava, "\r\nTo: <sip:");
	if(rozhodovani == 2)
		strcat(buffer->zaslana_zprava, message->adresa);
	else{
		strcat(buffer->zaslana_zprava, matice->user);
		strcat(buffer->zaslana_zprava, "@");
		strcat(buffer->zaslana_zprava, matice->cilova_ip);
	}
	strcat(buffer->zaslana_zprava, ">\r\n");
	if(rozhodovani == 2)
		strcat(buffer->zaslana_zprava, message->call_id);
	else
		strcat(buffer->zaslana_zprava, matice->call_id);
	strcat(buffer->zaslana_zprava, "\r\nCSeq: ");
	strcat(buffer->zaslana_zprava, cseq);
	strcat(buffer->zaslana_zprava, " ");
	strcat(buffer->zaslana_zprava, matice->metoda);
	strcat(buffer->zaslana_zprava, "\r\nExpires: ");
	strcat(buffer->zaslana_zprava, expires);
	strcat(buffer->zaslana_zprava, "\r\nContent-Length: ");
	if(rozhodovani == 2){
		strcat(buffer->zaslana_zprava, content);
		strcat(buffer->zaslana_zprava, "\r\n");
		strcat(buffer->zaslana_zprava, "Content-Type: text/plain;charset=UTF-8\r\n");
	}
	else	
		strcat(buffer->zaslana_zprava, "0\r\n");
	if(rozhodovani == 1){//Pokud je vyzadovan radek Autorization
		strcat(buffer->zaslana_zprava, "Authorization: Digest username=\"");
		strcat(buffer->zaslana_zprava, matice->user);
		strcat(buffer->zaslana_zprava, "\", realm=\"");
		strcat(buffer->zaslana_zprava,matice->realm);
		strcat(buffer->zaslana_zprava, "\", nonce=\"");
		strcat(buffer->zaslana_zprava,matice->nonce);
		strcat(buffer->zaslana_zprava, "\", uri=\"sip:");
		strcat(buffer->zaslana_zprava, matice->user);
		strcat(buffer->zaslana_zprava, "@");
		strcat(buffer->zaslana_zprava, matice->cilova_ip);
		strcat(buffer->zaslana_zprava, "\", algorithm=MD5, response=\"");
		strcat(buffer->zaslana_zprava, md5_zprava->md5);
		strcat(buffer->zaslana_zprava, "\"\r\n");
	}
	strcat(buffer->zaslana_zprava, "\r\n");
	if(rozhodovani == 2)
		strcat(buffer->zaslana_zprava, message->zprava);
}

// Funkce pro parsovani udaju (nonce, realm) z prijate zpravy od serveru.
void ziskej_udaje(char hledany_vyraz[], Tzprava *matice, Tbuf_zprava *buffer, bool nonce){
	char *p_tmp = NULL;// Promenna pro ulozeni zacatku hledaneho vyrazu ve zprave
	char *pole_tmp = NULL;// Pomocne pole vyuzivane pro ulozeni pozadovaneho udaje
	bool uvozovka = false;// Promenna udavajici zda byla zadana prvni uvozovka
	int uvozovka_2 = 0;// Promenna pro pocitani poctu uvozovek
	int i = 0;// Pomocna promenna vyuzivana pri prochazeni pole
	int j = 0;;// Pomocna promenna vyuzivana pri prochazeni pole

	//Ulozeni zacatku hledaneho vyrazu v prijate zprave
	p_tmp = strstr(buffer->prijata_zprava, hledany_vyraz);
	//Alokace pameti podle velikosti zbyvajici zpravy Cela_zprava - pozice_hledaneho_prvku
	if((pole_tmp = (char *) malloc(strlen(p_tmp))) == NULL){
		printfERR(E_MEMORY);
		raise(SIGUSR1);
	}

	memset(pole_tmp, 0, strlen(p_tmp));
	//Cyklus starajici se o nacteni hodnoty mezi "...."
	while(uvozovka_2 != 2){
		if((uvozovka == true) && (p_tmp[i] != '"')){
			pole_tmp[j] = p_tmp[i];
			j++;
		}
		if(p_tmp[i] == '"'){
			uvozovka = true;
			uvozovka_2++;
		}
		i++;
	}
	pole_tmp[strlen(pole_tmp)] = '\0';

	//Pokud by byl udaj vetsi nez je buffer ve strukture
	if(strlen(pole_tmp) > MAX_BUFFER_2){
		free(pole_tmp);
		printfERR(E_MAX_BUFFER);
		raise(SIGUSR1);
	}

	// Doplneni koncoveho nuloveho znaku retezce
	if(nonce == true)
		strcpy(matice->nonce, pole_tmp);
	else
		strcpy(matice->realm, pole_tmp);


	free(pole_tmp);
	pole_tmp = NULL;
}

/*Funkce pro vypisovani chybovych hlaseni. Navic ukoncuje v pripade chyby program
 *s patricnym chybovym kodem.                                                   */
void printfERR(int error)
{
  fprintf(stderr, "%s\n", ERROR[error]);
  /* Promnena error odkazuje do pole retezcu obsahujici chybove hlaseni. Pole je
   * cislovane od 0.Z tohoto duvodu je potreba zvysit navratovy kod o 1. Jinak
   * by v pripade chyby mohlo dojit k navratovemu kodu cislo 0 - coz je pro
   * navratovy kod pro spravny prubeh programu.*/
	//uvolni_pamet();
  //exit(error + 1);
}

//Funkce, ktera sestavi MD5 retezec, podle zadanych kriterii.
void vytvor_md5(Tzprava *matice, Tmd5 *md5_zprava){
	unsigned char digest[16];// Pole vyuzivane pri generovani MD5 posloupnosti
	MD5_CTX c;// Promenna vyuzivana pri generovani MD5 posloupnosti
	char str_tmp[200];//Pomocne pole pro ulozeni pripravene zpravy pred generovanim MD5
	
	//Priprava parametru pro generovani MD5 posloupnosti
	for(int i = 0; i < 3; i++){
		memset(str_tmp, 0, 200);//Vynulovani pomocneho pole
		/* Poskladani retezce, z ktereho budeme generovat MD5 posloupnost.
		   user:realm:password.*/
		if(i == 0){
			strcpy(str_tmp, matice->user);
			strcat(str_tmp, ":");
			strcat(str_tmp, matice->realm);
			strcat(str_tmp, ":");
			strcat(str_tmp, matice->password);
		}
		// metoda:sip:user@server
		if(i == 1){
			strcpy(str_tmp, matice->metoda);
			strcat(str_tmp, ":sip:");
			strcat(str_tmp, matice->user);
			strcat(str_tmp, "@");
			strcat(str_tmp, matice->cilova_ip);//MOZNA ZAMENIT ZA MOU ADRESU
		}
		// MD5(user:realm:password):nonce:MD5(metoda:sip:user@server)
		if(i == 2){
			strcpy(str_tmp, md5_zprava->ha_1);
			strcat(str_tmp, ":");
			strcat(str_tmp, matice->nonce);
			strcat(str_tmp, ":");
			strcat(str_tmp, md5_zprava->ha_2);
			str_tmp[strlen(str_tmp)] = '\0';
		}

		//Generovani MD5 posloupnosti
		MD5_Init(&c);
		MD5_Update(&c, str_tmp, strlen(str_tmp));
		MD5_Final(digest, &c);
	
		//Prevod MD5 posloupnosti ze 16 soustavy na retezec
		for (int n = 0; n < 16; ++n){
			if( i == 0)
				snprintf(&(md5_zprava->ha_1[n*2]), 16*2, "%02x", (unsigned int)digest[n]);
			if( i == 1)
				snprintf(&(md5_zprava->ha_2[n*2]), 16*2, "%02x", (unsigned int)digest[n]);
			if( i == 2)
				snprintf(&(md5_zprava->md5[n*2]), 16*2, "%02x", (unsigned int)digest[n]);
		}

		//Doplneni na konec retezce nulovy znak ukoncujici retezec
		if( i == 0)
			md5_zprava->ha_1[32] = '\0';
		if( i == 1)
			md5_zprava->ha_2[32] = '\0';
		if( i == 2)
			md5_zprava->md5[32] = '\0';

	}
}

//Funkce pro vygenerovani nahodnych sekvenci do zaslane zpravy a nastaveni udaju do struktury.
void generuj_hodnoty(Tzprava *matice, Todeslana_zprava *message, int i){
	char retezec_tmp [20]; // Pomocny retezec vyuzivany pri generovani hodnot
	unsigned int nahodne_cislo;//Pomocna promenna pro ulozeni nahodneho cisla

	//generovani tag
	nahodne_cislo = rand();
	//Prevod vygenerovaneho nahodneho cisla na retezec.
	snprintf(retezec_tmp, 19, "%d", nahodne_cislo);
	if(i == 1)
		strcat(matice->tag, retezec_tmp);
	else{
		memset(message->tag, 0, MAX_BUFFER);
		strcpy(message->tag, "tag="); 
		strcat(message->tag, retezec_tmp);	
	}

	//generovani Call-ID
	memset(retezec_tmp, 0, 20);//Vynulovani pole
	nahodne_cislo = rand();
	snprintf(retezec_tmp, 19, "%d", nahodne_cislo);
	if(i == 1)
		strcat(matice->call_id, retezec_tmp);
	else{
		memset(message->call_id, 0, MAX_BUFFER);
		strcpy(message->call_id, "Call-ID: "); 
		strcat(message->call_id, retezec_tmp);
	}

	//generovani branch
	memset(retezec_tmp, 0, 20);
	nahodne_cislo = rand();
	snprintf(retezec_tmp, 19, "%d", nahodne_cislo);
	if( i == 1)
		strcat(matice->branch, retezec_tmp);
	else{
		memset(message->branch, 0, MAX_BUFFER);
		strcpy(message->branch, "branch=z9hG4bK");
		strcat(message->branch, retezec_tmp);
	}
}

// Funkce pro ziskani cisla typu a nazvu odpovedi od serveru na nas pozadavek
void cislo_odpovedi(Tbuf_zprava *buffer){
  const char hledany_vyraz[] = "SIP/2.0 ";/* Konstatni retezec obsahujici hledany
											 retezec.*/
  char *p_tmp = NULL;/* Pomocny ukazatel pro ulozeni zacatku, kde zacina hledany 
						retezec s pozadovanou odpovedi serveru.*/
  int i = strlen(hledany_vyraz);/*Pomocna promenna vyuzivana jako zarazka, odkud
								  zacina hledany vyraz.*/
  char tmp[MAX_BUFFER_2];//Pomocnne pole
  int j = 0;//Pomocna promenna vyuzita pri ukladani znaku do pomocneho pole

	//Ulozeni pozice, kde se nachazi hledany retezec SIP/2.0
  p_tmp = strstr(buffer->prijata_zprava, hledany_vyraz);
  if(p_tmp == NULL){
    printfERR(E_ODPOVED_SERVER);
	raise(SIGUSR1);
  }

	//Cyklus, ktery zkopiruje ciselnou odpoved od serveru do pomocneho pole
  while((p_tmp[i] >= '0') && (p_tmp[i] <= '9')){
    tmp[j] = p_tmp[i];
    j++;
    i++;
    if(j > 3){
        printfERR(E_TYP_ODPOVED);
		raise(SIGUSR1);
	}
  }
  tmp[j] = '\0';
	buffer->typ_odpovedi = atoi(tmp);//Prevod retezec odpovedi na cislo

	//Zpracovani nazvu odpovedi od serveru
	memset(tmp, 0, MAX_BUFFER_2);

	j = 0;
	i++;

	//Zkopiruje nazev odpovedi od serveru do pomocneho pole
	while(p_tmp[i] != '\r'){
		tmp[j] = p_tmp[i];
		j++;
		i++;
	}
	
	tmp[j] = '\0';
	strcpy(buffer->nazev_odpovedi, tmp);
}

/* Funkce pro formatovani vypisu vystupu programu na obrazovku. 1 = Pozadavek na server.
   2 = pokud se jedna o odpoved server. */
void vypis_odpovedi(Tzprava *matice, int typ_tisku, Tbuf_zprava *buffer, Todeslana_zprava *message){
	switch(typ_tisku){
		case 1:
			printf("%d %s %s@%s", matice->cseq, matice->metoda, matice->user, matice->moje_ip);
			break;
		case 2:
			printf("%d %d %s %s@%s", matice->cseq, buffer->typ_odpovedi, buffer->nazev_odpovedi, matice->user, matice->moje_ip);
			break;
		case 3:
			printf("%d %s %s@%s", matice->cseq, matice->metoda, matice->user, matice->moje_ip);
			break;
		case 4:
			printf("%d UNREGISTER %s@%s", matice->cseq, matice->user, matice->moje_ip);
			break;
	}

	if((typ_tisku == 1) || (typ_tisku == 2) || (typ_tisku == 4)){
		if(matice->muj_port != 5060)
				printf(":%s", matice->muj_port_char);
		printf(" %s", matice->cilova_ip);
		if(matice->port_server != 5060)
			printf(":%s ", matice->port_server_char);
	}
	else{
		if(matice->muj_port != 5060)
				printf(":%s", matice->muj_port_char);
		printf(" %s", message->adresa);
		if(message->adresa_port != 5060)
			printf(":%s", message->adresa_port_char);
		printf(" %s",message->zprava);
	}
	printf("\n");
}

// Funkce pro zpracovani signalu
void zpracuj_signal(int cislo_signalu){
	switch (cislo_signalu) {
    	case SIGTERM:
        	pozadovane_odhlaseni = true;
 			break;

		case SIGQUIT:
        	pozadovane_odhlaseni = true;
			break;

		case SIGINT:
        	pozadovane_odhlaseni = true;
			break;

		case SIGALRM:
			alarm_zapnut = false;
			break;

		case SIGUSR1:
			uvolni_pamet();
			exit(1);
    }
}

/* Funkce pro nastaveni vychozich hodnot struktury obsahujici informace pro sestaveni
  zprav pro server.*/
void nastav_vychozi_hodnoty(Tzprava *matice, Todeslana_zprava *message){
	char tmp[6];

	strcpy(matice->tag, "tag="); 
	strcpy(matice->call_id, "Call-ID: "); 
	strcpy(matice->branch, "branch=z9hG4bK");
	matice->odpoved = false;
	matice->cseq = 0;
	strcpy(matice->metoda, "REGISTER");
	matice->muj_port = 32866;
	sprintf(tmp, "%d", matice->muj_port);
	strcpy(matice->muj_port_char, tmp);

	matice->port_server = atoi(matice->port_server_char);
	// Osetreni v pripade, ze bylo zadane moc vysoke cislo portu
	if(matice->port_server > 65535){
		printfERR(E_PORT);
		raise(SIGUSR1);
	}
}

//Funkce slouží k vyhledání řetězce ve větším poli. 
bool ziskat_udaje(char hled_vyraz[], char vstup[], char vystup_tmp[]){
  int i = 0;
	
	if(strlen(hled_vyraz) >= strlen(vstup))
		return false;

  for(unsigned int tmp_i = 0; tmp_i <= strlen(hled_vyraz); tmp_i++){
    if(hled_vyraz[tmp_i] != vstup[tmp_i]){
      i = tmp_i;
      break;
    }
  }

  for(unsigned b = i; b <= strlen(vstup); b++){
    if((((vstup[b]!= '\0') && (vstup[b] != '\040')) || (vstup[b] == ':')) && (vstup[b] != '\n'))
      vystup_tmp[b - i] = vstup[b];
    else{
      vystup_tmp[b-i] = '\0';
      break;
    }
  }
	return true;
}

//Funkce zpracuje soubor profiles.txt a nastavi udaje z nej do struktury
int zpracuj_soubor(char *soubor, Tzprava *matice){
  FILE *fr;
  int i = 0;
  char tmp_pole[500];
  char tmp_cislo[100];

  if((fr = fopen(soubor, "r")) == NULL){
    printfERR(E_OPEN_FILE);
	raise(SIGUSR1);
  }

  while(fgets(tmp_pole, 500, fr) != NULL){
    switch (i){
    case 0:
		if(ziskat_udaje("server=", tmp_pole, matice->cilova_ip) == false){
			printfERR(E_SERVER);
			raise(SIGUSR1);
		}

		zpracuj_port(matice->cilova_ip, matice->port_server_char);
        break;
    case 1:
      if(ziskat_udaje("username=", tmp_pole, matice->user) == false){
		printfERR(E_USER);
		raise(SIGUSR1);
	}
      break;
    case 2:
      if(ziskat_udaje("password=", tmp_pole, matice->password) == false){
		printfERR(E_PASSWORD);
		raise(SIGUSR1);
	}
      break;
    case 3:
      if(ziskat_udaje("expires=", tmp_pole, tmp_cislo) == false)	
		matice->expires = 3600;
		else
      		matice->expires = atol(tmp_cislo);
      break;
    default:
      fclose(fr);
      return 2;
    }
    i++;
  }

  if(fclose(fr) == EOF)
    return 1;

  return 0;
}

//Funkce starajici se o uvolnnei dynamicky alokovane pameti
void uvolni_pamet(Todeslana_zprava *message){
	free(soubor_profilu);
	free(soubor_zpravy);

	soubor_profilu = NULL;
	soubor_zpravy = NULL;
}

//Funkce pro parsovani adresy serveru a portu
void zpracuj_port(char ip_adresa[], char port[]){
	char tmp_pole[500];//Pomocne pole 
	char *p_tmp;//Pomocny ukazatel

	/* Kontrolova zda je soucasti adresy take port. Nasledne probiha zpracovani 
	   portu a pote adresy.*/
	if((p_tmp = strchr(ip_adresa, ':')) != NULL){
		// Nulovani pole
		memset(tmp_pole, 0, MAX_BUFFER_3);
		strcpy(tmp_pole, ip_adresa);
		//Pokud bylo zadano nesmyslne vysoke cislo portu
		if(strlen((p_tmp + 1)) > 5){
			printfERR(E_PORT);
			raise(SIGUSR1);
		}
		strcpy(port, (p_tmp + 1));
		memset(ip_adresa, 0, MAX_BUFFER_3);
		strncpy(ip_adresa, tmp_pole, (p_tmp)-(ip_adresa));
	}

	// Pokud nebyl zadan port, tak se nastavi vychozi port 5060
	else
		strcpy(port, "5060");

	p_tmp = NULL;
}

/* Funkce pro zjisteni me adresy, pokud neni server nastaven na localhost. Dale 
   funkce ulozi zjistenou adresu do pole. Funkce byla prevzata z manualove stranky:
   http://man7.org/linux/man-pages/man3/getifaddrs.3.html, a nasledne upravena
   pro me pouziti.*/
void zjisti_moji_ip(char *moje_ip){
	struct ifaddrs *ifaddr, *ifa;
    int family, s, n;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1){
		printfERR(E_MOJE_IP);
		raise(SIGUSR1);
	}
    	

    for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
	    if (ifa->ifa_addr == NULL)
	        continue;

        family = ifa->ifa_addr->sa_family;

        if (family == AF_INET) {
	        s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0){
            	printfERR(E_MOJE_IP);
				raise(SIGUSR1);
			}

			if(strcmp(host, "127.0.0.1") != 0)
				strcpy(moje_ip, host);
        }
    }

    freeifaddrs(ifaddr);
    

}
