package de.hpi.ddm.actors;

import java.io.Serializable;
import java.util.*;
import java.util.stream.Collectors;

import akka.actor.AbstractLoggingActor;
import akka.actor.ActorRef;
import akka.actor.PoisonPill;
import akka.actor.Props;
import akka.actor.Terminated;
import de.hpi.ddm.structures.BloomFilter;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

public class Master extends AbstractLoggingActor {

    ////////////////////////
    // Actor Construction //
    ////////////////////////

    public static final String DEFAULT_NAME = "master";

    public static Props props(final ActorRef reader, final ActorRef collector, final BloomFilter welcomeData) {
        return Props.create(Master.class, () -> new Master(reader, collector, welcomeData));
    }

    public Master(final ActorRef reader, final ActorRef collector, final BloomFilter welcomeData) {
        this.reader = reader;
        this.collector = collector;
        this.workers = new ArrayList<>();
        this.freeWorkers = new LinkedList<>();
        this.largeMessageProxy = this.context().actorOf(LargeMessageProxy.props(), LargeMessageProxy.DEFAULT_NAME);
        this.hintsToCrack = new LinkedList<>();
        this.passwordsToCrack = new LinkedList<>();
        this.initialized = false;
        this.isAllRecordsReceived = false;
        this.numberOfRecords = 0;
        this.idToPasswordDataMap = new HashMap<>();
        this.welcomeData = welcomeData;
    }

    ////////////////////
    // Actor Messages //
    ////////////////////

    @Data
    public static class StartMessage implements Serializable {
        private static final long serialVersionUID = -50374816448627600L;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class BatchMessage implements Serializable {
        private static final long serialVersionUID = 8343040942748609598L;
        private List<String[]> lines;
    }

    @Data
    public static class RegistrationMessage implements Serializable {
        private static final long serialVersionUID = 3303081601659723997L;
    }

    // supreme custom classes below
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class HintResultMessage implements Serializable {
        private static final long serialVersionUID = 393040942748609598L;
        private int passwordId;
        private Character missingChar;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class PasswordResultMessage implements Serializable {
        private static final long serialVersionUID = 393040944448111598L;
        private String plainPassword;
        private PasswordData passwordData;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class HintData implements Serializable {
        int passwordId;
        String[] hashedHints;
        int indexCharToCheck;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class PasswordData implements Serializable {
        int id;
        String name;
        List<Character> charsInPassword;
        String hashedPassword;
        int numRemainingHintsToCrack;
    }
    /////////////////
    // Actor State //
    /////////////////

    private final ActorRef reader;
    private final ActorRef collector;
    private final List<ActorRef> workers;
    private final ActorRef largeMessageProxy;
    private final BloomFilter welcomeData;

    // supreme custom queues
    private final LinkedList<ActorRef> freeWorkers;
    private final LinkedList<HintData> hintsToCrack;
    private final LinkedList<PasswordData> passwordsToCrack;

    private Map<Integer, PasswordData> idToPasswordDataMap;
    private int numberOfRecords;
    private Boolean isAllRecordsReceived;
    private Boolean initialized; // false until first message from reader received to set the following 3 parameters once and for all:
    private char[] possibleChars; // the "char universe" stays the same
    private int passwordLength; // also stays the same

    private long startTime;

    /////////////////////
    // Actor Lifecycle //
    /////////////////////

    @Override
    public void preStart() {
        Reaper.watchWithDefaultReaper(this);
    }

    ////////////////////
    // Actor Behavior //
    ////////////////////

    @Override
    public Receive createReceive() {
        return receiveBuilder()
                .match(StartMessage.class, this::handle)
                .match(BatchMessage.class, this::handle)
                .match(Terminated.class, this::handle)
                .match(RegistrationMessage.class, this::handle)
                .match(HintResultMessage.class, this::handle)
                .match(PasswordResultMessage.class, this::handle)
                .matchAny(object -> this.log().info("Received unknown message: \"{}\"", object.toString()))
                .build();
    }

    protected void handle(StartMessage message) {
        this.startTime = System.currentTimeMillis();
        this.reader.tell(new Reader.ReadMessage(), this.self());
    }

    protected void handle(BatchMessage message) {
        System.out.println("received batch");
        // TODO: This is where the task begins:
        // - The Master received the first batch of input records.
        // - To receive the next batch, we need to send another ReadMessage to the reader.
        // - If the received BatchMessage is empty, we have seen all data for this task.
        // - We need a clever protocol that forms sub-tasks from the seen records, distributes the tasks to the known workers and manages the results.
        //   -> Additional messages, maybe additional actors, code that solves the subtasks, ...
        //   -> The code in this handle function needs to be re-written.
        // - Once the entire processing is done, this.terminate() needs to be called.

        // Info: Why is the input file read in batches?
        // a) Latency hiding: The Reader is implemented such that it reads the next batch of data from disk while at the same time the requester of the current batch processes this batch.
        // b) Memory reduction: If the batches are processed sequentially, the memory consumption can be kept constant; if the entire input is read into main memory, the memory consumption scales at least linearly with the input size.
        // - It is your choice, how and if you want to make use of the batched inputs. Simply aggregate all batches in the Master and start the processing afterwards, if you wish.

        // TODO: Stop fetching lines from the Reader once an empty BatchMessage was received; we have seen all data then

        // thought: new todo, probably we want to double check, whether the processing is done, before we
        // todo terminate, so a boolean for that might be nice? or an enum that works
        //  like a switch: first, nothing. then: all records processed. then: all hints cracked. then: all passwords cracked
        if (message.getLines().isEmpty()) {
            this.isAllRecordsReceived = true;
            return;
        }

        // if first BatchMessage, set what stays the same
        if (!this.initialized) {
            this.initialized = true;
            this.possibleChars = message.getLines().get(0)[2].toCharArray(); //ABCDEFGHIJK
            this.passwordLength = Integer.parseInt(message.getLines().get(0)[3]); // 10
        }

        LinkedList<String[]> recordsToProcess = new LinkedList<>(message.getLines());

        while (!recordsToProcess.isEmpty()) {
            String[] recordToProcess = recordsToProcess.removeFirst();
            String[] hashedHints = Arrays.copyOfRange(recordToProcess, 5, recordToProcess.length);

            // create password data and store in map for later look up
            PasswordData pwData = new PasswordData();
            pwData.id = Integer.parseInt(recordToProcess[0]);
            pwData.name = recordToProcess[1];
            pwData.hashedPassword = recordToProcess[4];
            pwData.numRemainingHintsToCrack = hashedHints.length;
            pwData.charsInPassword = new String(this.possibleChars).chars().mapToObj(c -> (char) c).collect(Collectors.toList());
            this.idToPasswordDataMap.put(pwData.id, pwData);

            // create hint data and queue hints as often as there are chars in the alphabet
            for (int i = 0; i < this.possibleChars.length; i++) {
                HintData hintData = new HintData();
                hintData.passwordId = Integer.parseInt(recordToProcess[0]);
                hintData.hashedHints = hashedHints;
                hintData.indexCharToCheck = i;
                this.hintsToCrack.add(hintData);
            }

            this.numberOfRecords++;
        }

        // while there are free workers and work, give workers work
        dispatchFreeWorkers();

        if(!this.isAllRecordsReceived) {
            this.reader.tell(new Reader.ReadMessage(), this.self());
        }
    }

    protected void handle(HintResultMessage message) {
        Character crackedChar = message.missingChar;
        PasswordData pwData = idToPasswordDataMap.get(message.passwordId);
        if(crackedChar != null) {
            pwData.charsInPassword.remove(crackedChar);
            pwData.numRemainingHintsToCrack--;
            idToPasswordDataMap.put(pwData.id, pwData);
            this.log().info("remove char {} for password {}", crackedChar, pwData.id);
        }

        // if no more hints to crack for a password, password is ready to be cracked
        if(pwData.numRemainingHintsToCrack == 0) {
            passwordsToCrack.add(pwData);
            this.log().info("add password to queue");
        }

        // worker is done with cracking the hint, he can get new work assigned
        ActorRef worker = this.sender();
        this.freeWorkers.add(worker);
        dispatchFreeWorkers();
    }

    protected void handle(PasswordResultMessage message) {
        this.log().info("Cracked Password for ID {}, {}: {}",  message.getPasswordData().getId(), message.getPasswordData().getName(), message.getPlainPassword());
        this.collector.tell(new Collector.CollectMessage("Cracked Password for ID "+message.getPasswordData().getId()+", "+message.getPasswordData().getName()+": "+message.getPlainPassword()), this.self());
        this.numberOfRecords--;
        // as the worker is done with cracking the password, he can get new work assigned
        ActorRef worker = this.sender();
        this.freeWorkers.add(worker);
        dispatchFreeWorkers();
    }

    protected void dispatchFreeWorkers() {
        System.out.println("Dobby is a free worker!");
        if(this.isAllRecordsReceived && this.numberOfRecords == 0){
            System.out.println("let's terminate");
            this.terminate();
        }

        // as long as there are free workers, assign them available work
        while (!this.freeWorkers.isEmpty() && (!this.hintsToCrack.isEmpty() || !this.passwordsToCrack.isEmpty())) {
            if (!this.passwordsToCrack.isEmpty()) {
                ActorRef worker = this.freeWorkers.removeFirst();
                worker.tell(new Worker.WorkOnPasswordMessage(passwordsToCrack.removeFirst(), this.passwordLength), this.self());
                System.out.println("Dobby is working on Password");
            } else if (!this.hintsToCrack.isEmpty()) {
                ActorRef worker = this.freeWorkers.removeFirst();
                worker.tell(new Worker.WorkOnHintMessage(possibleChars, hintsToCrack.removeFirst()), this.self());
                System.out.println("Dobby is working on Hint");
            }
        }
    }

    protected void terminate() {
        System.out.println("terminating");
        this.collector.tell(new Collector.PrintMessage(), this.self());

        this.reader.tell(PoisonPill.getInstance(), ActorRef.noSender());
        this.collector.tell(PoisonPill.getInstance(), ActorRef.noSender());

        for (ActorRef worker : this.workers) {
            this.context().unwatch(worker);
            worker.tell(PoisonPill.getInstance(), ActorRef.noSender());
        }

        this.self().tell(PoisonPill.getInstance(), ActorRef.noSender());

        long executionTime = System.currentTimeMillis() - this.startTime;
        this.log().info("Algorithm finished in {} ms", executionTime);
    }

    protected void handle(RegistrationMessage message) {
        this.context().watch(this.sender());
        this.workers.add(this.sender());
        this.freeWorkers.add(this.sender());
        this.log().info("Registered {}", this.sender());

        this.largeMessageProxy.tell(new LargeMessageProxy.LargeMessage<>(new Worker.WelcomeMessage(this.welcomeData), this.sender()), this.self());

        dispatchFreeWorkers();
    }

    protected void handle(Terminated message) {
        this.context().unwatch(message.getActor());
        this.workers.remove(message.getActor());
        this.log().info("Unregistered {}", message.getActor());
    }
}
