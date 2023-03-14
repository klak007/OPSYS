#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define FALSE 0
#define TRUE 1
#define NONE -1
#define DONE -1
#define BUSY 1
#define FREE 0
#define MAXTIME 100
#define MAXCPU 12
#define MAXJOBS 100
#define FCFS 0
#define SJF 1
#define SRTF 2
#define RR 3
#define PPFCFS 4
#define PPSRTF 5
#define PNPFCFS 6
#define ENDOFJOBLIST -1

typedef struct
{
    int handle;         // numer procesu potrzebny do identyfikacji (drukowanie)
    int job;            // index procesu w tablicy procesów: potrzebny do odnalezienia rekordu procesu w cpu
    int cpu;            // cpu
    int completed;      //
    int priority;       //
    int preemptive;     // wydziedziczany
    int arrivalTime;    // AT kwant w którym proces przyszedł
    int firstResponse;  // FR kwant w którym proces pierwszy raz otrzymał dostęp
    int burstTime;      // BT czas wykonania
    int responseTime;   // RT czas oczekiwania od przyjścia, to pierwszego dostępu na CPU
    int turnaroundTime; // TAT całkowity czas od przyjścia do zakończonia TAT=BT+WT
    int remainingTime;  // ile czasu jeszcze trzeba obrabiać
    int waitingTime;    // WT czas procesu spędzony na oczekiwaniu na CPU WT=TAT-BT
    int completionTime; // ET kwant w którym został zakończony
} tJob;

typedef struct
{
    // int busy;
    int job;
} tCpu;

typedef struct
{
    unsigned int cpuTotalNumber;  // ilość procesorów
    unsigned int policyCode;      // kod algorytmu porządkowania
    unsigned int currentTimeSlot; // symulowany czas pracy maszyny
    unsigned int timeStep;        // nie będzie używany
    int newOnJobList;             // dla celów symulacji
    int endOfJobList;             // dla celów symulacji
    int jobsToDo;                 // liczba zadań nieukończonych
    tCpu cpu[MAXCPU];
} tMachine;

tJob jobs[MAXJOBS];
tMachine machine;
char jobsLine[100] = "";
FILE *file;
int jobsNumber = 0; // liczba procesów

void init() // inicjuje struktury maszyny, procesorów i zadań, otwiera plik testowy
{
   // system("clear");
    file = fopen("input3.in", "r");
    machine.cpuTotalNumber = 1;
    machine.currentTimeSlot = 0;
    machine.timeStep = 1;
    machine.newOnJobList = 0;
    machine.endOfJobList = 0;
    machine.jobsToDo = 0;
    for (int i = 0; i < MAXCPU; i++)
    {
        machine.cpu[i].job = NONE;
    }
    for (int i = 0; i < MAXJOBS; i++)
    {
        jobs[i].arrivalTime = NONE;
        jobs[i].cpu = NONE;
        jobs[i].completed = 0;
        jobs[i].burstTime = NONE;
        jobs[i].completionTime = NONE;
        jobs[i].firstResponse = NONE;
        jobs[i].handle = NONE;
        jobs[i].job = NONE;
        jobs[i].preemptive = NONE;
        jobs[i].remainingTime = NONE;
        jobs[i].priority = NONE;
        jobs[i].responseTime = NONE;
        jobs[i].turnaroundTime = NONE;
        jobs[i].waitingTime = NONE;
    }
}

void done() // zamyka plik testowy
{
    fclose(file);
}

int readParams(int argc, char *argv[]) // odczytuje parametry uruchomienia programu i inicjuje na ich podstawie algorytm, ilość CPU i krok czasu
{
    if (argc < 2)
    {
        printf("wymagane argumenty!\n");
        return 0;
    }

    machine.policyCode = (atoi(argv[1]));

    if (argc > 2)
    {
        if (strlen(argv[2]) == 1)
        {
            machine.cpuTotalNumber = atoi(argv[2]);
        }
    }

    if (argc > 3)
    {
        if (strlen(argv[3]) == 1)
        {
            machine.timeStep = atoi(argv[3]);
        }
    }

    return 1;
}

int addToJobs() // dodaje linię zadań, rozkodowuje ją, zapisuje do listy zadań i zwraca sumaryczną liczbę zadań
{

    int parCode[100] = {0};
    int charIndex = 0, parIndex = 0, len;
    if (fgets(jobsLine, sizeof(jobsLine), file) != NULL)
    {

        len = strlen(jobsLine);
        jobsLine[len] = '\0';

        for (charIndex = 0; charIndex < len; charIndex++)
        {
            if (jobsLine[charIndex] >= '0' && jobsLine[charIndex] <= '9')
            {
                parCode[parIndex] = parCode[parIndex] * 10 + (jobsLine[charIndex] - '0');
            }
            if (!(jobsLine[charIndex] >= '0' && jobsLine[charIndex] <= '9') || charIndex == len - 1)
            {
                switch ((parIndex - 1) % 3)
                {
                case 0:
                    jobs[jobsNumber + (parIndex - 1) / 3].handle = parCode[parIndex];            // numer procesu
                    jobs[jobsNumber + (parIndex - 1) / 3].job = jobsNumber + (parIndex - 1) / 3; // numer w tablicy
                    break;
                case 1:
                    jobs[jobsNumber + (parIndex - 1) / 3].priority = parCode[parIndex];
                    break;
                case 2:
                    jobs[jobsNumber + (parIndex - 1) / 3].burstTime = parCode[parIndex];                                   // czas CPU potrzebny na wykonie
                    jobs[jobsNumber + (parIndex - 1) / 3].arrivalTime = parCode[0];                                        // kwant przyjścia
                    jobs[jobsNumber + (parIndex - 1) / 3].firstResponse = NONE;                                            // w chwili przyjścia brak dostępu
                    jobs[jobsNumber + (parIndex - 1) / 3].turnaroundTime = 0;                                              // w chwili przyjścia jeszcze nie obrabiany
                    jobs[jobsNumber + (parIndex - 1) / 3].remainingTime = jobs[jobsNumber + (parIndex - 1) / 3].burstTime; // co najmniej tyle czasu jeszcze trzeba
                    jobs[jobsNumber + (parIndex - 1) / 3].waitingTime = 0;                                                 // w chwili przyjścia jeszcze nie czekał
                    jobs[jobsNumber + (parIndex - 1) / 3].completionTime = NONE;                                           // w chwili przyjścia nie jest jeszcze znany
                    machine.jobsToDo++;
                    break;
                }

                parIndex++;
            }
        }
        jobsNumber += (parIndex - 1) / 3;

        return jobsNumber;
    }
    return jobsNumber;
}

void moveJobs() // przesuwa zadania jeśli CPU o niższych numerach są nieobsadzone a CPU o wyższych są obsadzone
{
    int cpui, cpuj;
    for (cpui = 0; cpui < machine.cpuTotalNumber - 1; cpui++) // dla każdego procesora oprócz ostatniego
    {
        for (cpuj = cpui + 1; cpuj < machine.cpuTotalNumber; cpuj++) // dla każdego procesora za procesorem cpui
        {
            if ((machine.cpu[cpui].job == NONE) && (machine.cpu[cpuj].job != NONE)) // jeśli procesor o niższym numerze wolny, przesuń zadanie z procesora o wyższym numerze
            {
                machine.cpu[cpui].job = machine.cpu[cpuj].job; // zmień przypisanie zadania w cpu docelowym
                jobs[machine.cpu[cpuj].job].cpu = cpui;        // zmień przypsanie cpu w zadaniu
                machine.cpu[cpuj].job = NONE;                  // oznacz cpu żródłowe jako wolne
            }
        }
    }
}

void updateJobsStates() // uaktulania status dla zadania
{
    int jobi;
    for (jobi = 0; jobi < machine.endOfJobList; jobi++) // dla każdego zadania
    {
        if (jobs[jobi].cpu != NONE)
        {
            if (jobs[jobi].firstResponse == NONE)
                jobs[jobi].firstResponse = machine.currentTimeSlot;
            jobs[jobi].remainingTime -= machine.timeStep;
            if (jobs[jobi].remainingTime)
                jobs[jobi].turnaroundTime += machine.timeStep;

            if ((!jobs[jobi].remainingTime) && (!jobs[jobi].completed)) // zakończenie procesu
            {
                machine.cpu[jobs[jobi].cpu].job = NONE; // zwolnij processor
                jobs[jobi].completionTime = machine.currentTimeSlot - jobs[jobi].firstResponse;
                jobs[jobi].completed = 1;
                machine.jobsToDo--; // zmniejsz liczbę zadań niewykonanych
            }
        }
    }
}

void fcfs() // first come first serve
{
    int cpui;
    int jobi;

    for (cpui = 0; cpui < machine.cpuTotalNumber; cpui++) // dla każdego procesora
    {
        for (jobi = 0; jobi < machine.endOfJobList; jobi++) // dla każdego zadania
        {
            if ((machine.cpu[cpui].job == NONE) && (jobs[jobi].cpu == NONE) && (!jobs[jobi].completed)) // jeżeli wolny procesor i zadanie bez procesora i zadnie niezakończone
            {
                machine.cpu[cpui].job = jobs[jobi].job; // przypisz job do procesora
                jobs[jobi].cpu = cpui;                  // przypisz procesor do jobu
                break;
            }
        }
    }
}

int getShortestJobNumber() // znajdź najkrótszy nieuruchomiony i niezakończony job
{
    int jobi;
    int sJobNumber = NONE;
    int minSj = INT_MAX;
    for (jobi = 0; jobi < machine.endOfJobList; jobi++)
    {
        if ((!jobs[jobi].completed) && (jobs[jobi].cpu == NONE) && (jobs[jobi].burstTime < minSj)) // jeżeli zadanie niezakończone, nieobrabiane i krótsze
        {
            minSj = jobs[jobi].burstTime;
            sJobNumber = jobi;
        }
    }
    return sJobNumber;
}

void sjf() // shortest job first
{
    int cpui;
    int sjn;

    for (cpui = 0; cpui < machine.cpuTotalNumber; cpui++) // dla każdego procesora
    {
        if ((sjn = getShortestJobNumber()) != NONE) // znajdzć najkrótszy process, który nie jest uruchomiony na żadnym procesorze i nie jest zakończony
        {
            if (machine.cpu[cpui].job == NONE) // jeżeli wolny procesor i zadanie bez procesora i zadnie niezakończone i zadanie z najkrótszym czasem
            {
                machine.cpu[cpui].job = jobs[sjn].job; // przypisz job do procesora
                jobs[sjn].cpu = cpui;                  // przypisz procesor do jobu
            }
        }
    }
}

int getSrtJobNumber() // znajdź nieuruchomiony i niezakończony job o najkrótszym czasie do końca
{
    int jobi;
    int srtJobNumber = NONE;
    int minSrt = INT_MAX;
    for (jobi = 0; jobi < machine.endOfJobList; jobi++)
    {
        if ((!jobs[jobi].completed) && (jobs[jobi].cpu == NONE) && (jobs[jobi].remainingTime < minSrt)) // jeżeli zadanie niezakończone, nieobrabiane i krótsze
        {
            minSrt = jobs[jobi].remainingTime;
            srtJobNumber = jobi;
        }
    }
    return srtJobNumber;
}

int anyCpuFree()
{
    int noFree = TRUE;
    for (int cpui = 0; cpui < machine.cpuTotalNumber; cpui++)
    {
        noFree = noFree && (machine.cpu[cpui].job != NONE);
    }
    return !noFree;
}

int anyCpuWorking()
{
    int anyWorking = FALSE;
    for (int cpui = 0; cpui < machine.cpuTotalNumber; cpui++)
    {
        anyWorking = anyWorking || (machine.cpu[cpui].job != NONE);
    }
    return anyWorking;
}

int getLrtCpuNumber() // nieużywane: znajdź uruchomiony job o najdłuższym czasie do końca
{
    int cpui;
    int lrtCpuNumber = NONE;
    int maxLrt = INT_MIN;
    for (cpui = 0; cpui < machine.cpuTotalNumber; cpui++)
    {
        if ((!jobs[machine.cpu[cpui].job].remainingTime > maxLrt)) // jeżeli zadanie niezakończone, nieobrabiane i krótsze
        {
            maxLrt = jobs[machine.cpu[cpui].job].remainingTime;
            lrtCpuNumber = cpui;
        }
    }
    return lrtCpuNumber;
}

void srtf() // shortest remaining time first
{
    int cpui;
    int srtn;
    if (anyCpuFree())
    {
        // w pierwszej kolejności wolne procesory: jeżeli jest wolny procesor, to nie trzeba wydziedziczać
        for (cpui = 0; cpui < machine.cpuTotalNumber; cpui++) // dla każdego procesora
        {
            if ((srtn = getSrtJobNumber()) != NONE) // znajdzć proces z najkrótszym czasem do końca, który nie jest uruchomiony na żadnym procesorze i nie jest zakończony
            {

                if (machine.cpu[cpui].job == NONE) // jeżeli wolny procesor i zadanie bez procesora i zadanie niezakończone i zadanie z najkrótszym czasem do końca
                {
                    machine.cpu[cpui].job = jobs[srtn].job; // przypisz job do procesora
                    jobs[srtn].cpu = cpui;                  // przypisz procesor do jobu
                }
            }
        }
    }
    else
    {
        // jeżeli nie ma wolnego procesora, to wydziedzicz z procesora na którym jest zadanie z najdłuższym czasem do zakończenia
        for (cpui = 0; cpui < machine.cpuTotalNumber; cpui++) // dla każdego procesora
        {
            if ((srtn = getSrtJobNumber()) != NONE) // znajdz process z najkrótszym czasem do końca, który nie jest uruchomiony na żadnym procesorze i nie jest zakończony
            {
                if (jobs[srtn].remainingTime < jobs[machine.cpu[cpui].job].remainingTime) // jeżeli zadanie z najkrótszym czasem do końca krótsze od tego w procesorze
                {
                    // wydziedzicz zadanie
                    jobs[machine.cpu[cpui].job].cpu = NONE;
                    // nie trzeba usuwać w cpu bo poniżej nowe przypisanie
                    // przydziel zadanie
                    machine.cpu[cpui].job = jobs[srtn].job; // przypisz job do procesora
                    jobs[srtn].cpu = cpui;                  // przypisz procesor do job
                }
            }
        }
    }
}

void scheduler(int policyCode)
{
    switch (policyCode)
    {
    case FCFS:
        fcfs(); // przypisz zadania
        break;
    case SJF:
        sjf(); // przypisz zadania
        break;
    case SRTF:
        srtf(); // przypisz zadania
        break;
    default:
        fcfs(); // przypisz zadania
        break;
    }
}

void results()
{
    int cpui;
    printf("%3d ", machine.currentTimeSlot);
    for (cpui = 0; cpui < machine.cpuTotalNumber; cpui++)
    {
        if (machine.cpu[cpui].job != NONE)
        {
            printf("%d ", jobs[machine.cpu[cpui].job].handle);
        }
        else
        {
            printf(" -1 ");
        }
    }
    printf("\n");
}

void simulate()
{
    int loop;
    do
    {
        
        machine.newOnJobList = machine.endOfJobList; // ustaw newOnJobList na pierwsze nowe zadanie w kolejce (+1)
        machine.endOfJobList = addToJobs();          // pobierz zadania do kolejki i ustaw endOfJobList na osatnie zadanie w kolejce (+1)
        moveJobs();                                  // przesuń zadania na procesorach
        scheduler(machine.policyCode);               // wykonaj porządkowanie
        loop = anyCpuWorking();                      // musi być tutaj, żeby przez while() przeszła jedna linia ze wszystkimi zadaniami zakończonymi
        results();                                   // wydrukuj rezultaty
        updateJobsStates();                          // zaktulizuj postępy w zadaniach
        machine.currentTimeSlot += machine.timeStep;

    } while (loop);
}

int main(int argc, char *argv[])
{
    init();
    if (readParams(argc, argv))
    {
        simulate();
    }
    done();

    return 0;
}