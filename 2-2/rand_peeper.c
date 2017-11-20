#include <time.h>
#include <stdio.h>
#include <stdlib.h>

int main(){

    //int seed = 0x1480589317;
    //long qq = 0x5840066f1480590959;
    srand(0x); // Put the seed you observed in srand of the game and put the same seed here
    int i;
    int x;
    int y;
    for(i=0;i<100;i++){

        x = rand();
        //printf("%d ",x%4 + 1);
        y = x;
        x = x  >> 31;
        x = (unsigned)x >> 30;
        y += x;
        y = y%4;
        y = y - x;
        x = y ;
        x = x + 1;
        if(x==1){
             printf("4 ");
        }
        else if(x==2){
            printf("1 ");
        }
        else if(x==3){
            printf("2 ");
        }
        else if(x==4){
             printf("3 ");
        }
        printf("%d ",x);

    }

    return 0 ;
}
