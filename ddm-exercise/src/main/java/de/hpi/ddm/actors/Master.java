package de.hpi.ddm.actors;

import java.io.Serializable;
import java.util.*;

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
        this.hintsToCrack = new LinkedList<>();
        this.passwordsToCrack = new LinkedList<>();
        this.passwordPossibilities = new ArrayList<>();
        this.initialized = false;
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

    // new class for receiving the result from the worker
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class HintResultMessage implements Serializable {
        private static final long serialVersionUID = 393040942748609598L;
        private List<Integer> result;
        private String hashedPassword;
    }

    // new class for receiving the result from the worker
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class PasswordResultMessage implements Serializable {
        private static final long serialVersionUID = 393040944448609598L;
        private String plainPassword;
        private String hashedPassword;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class HintInformation {
        String[] hashedHints;
        String hashedPassword;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class PasswordInformation {
        Set<Character> passwordCharacters;
        String hashedPassword;
    }
    /////////////////
    // Actor State //
    /////////////////

    private final ActorRef reader;
    private final ActorRef collector;
    private final List<ActorRef> workers;

    // 2 queues: one for lines in the csv to process, one of workers to give these lines to:
    private final LinkedList<ActorRef> freeWorkers;
    private final LinkedList<HintInformation> hintsToCrack;
    // one more queue: for passwords to crack
    private final LinkedList<PasswordInformation> passwordsToCrack;

    private Boolean initialized; // false until first message from reader received to set the following:
    private char[] password; // the "char universe" stays the same
    private int passwordLength; // also stays the same
    private final List<char[]> passwordPossibilities;

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

    protected void handle(HintResultMessage message) {
        List<Integer> result = message.getResult();

        // result tells us which characters are _not_ in the string, so we know which are:
        Set<Character> passwordCharacters = new HashSet<Character>();
        for (char ch : this.password) {
            passwordCharacters.add(ch);
        }
        for (int i : result) {
            passwordCharacters.remove(this.password[i]);
        }
        System.out.println(passwordCharacters);
        // todo these two loops AND the set does not look like the most efficient solution

        // with the passwordCharacters cracked, a new
        // queue for passwordCracking work is necessary
        PasswordInformation pI = new PasswordInformation(passwordCharacters, message.getHashedPassword());
        passwordsToCrack.add(pI);

        // now, the worker is free again.
        ActorRef worker = this.sender();
        this.freeWorkers.add(worker);
        dispatchFreeWorkers();
    }

    protected void handle(PasswordResultMessage message) {
        // TODO: Send (partial) results to the Collector
        // this is a todo from thorsten, i feel like this oneliner gets the job done.. or does it? :D
        this.collector.tell(new Collector.CollectMessage(message.getPlainPassword()), this.self());


        ActorRef worker = this.sender();
        this.freeWorkers.add(worker);
        dispatchFreeWorkers();
    }

    protected void handle(BatchMessage message) {
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
        // terminate, so a boolean for that might be nice
        if (message.getLines().isEmpty()) {
            this.terminate();
            return;
        }

        // if first BatchMessage, set what stays the same:
        if (this.initialized == false) {
            this.initialized = true;
            this.password = message.getLines().get(0)[2].toCharArray(); //ABCDEFGHIJK
            this.passwordLength = Integer.parseInt(message.getLines().get(0)[3]); // 10
            // once, generate a list of strings, each with the password chars minus one
            // this is useful to let different workers work on solving different hints
            for (char charToLeave : this.password) {
                char[] passwordChars = new char[this.password.length - 1];
                int j = 0;
                for (char charToAdd : this.password) {
                    if (charToLeave == charToAdd) {
                        continue;
                    }
                    passwordChars[j++] = charToAdd;
                }
                this.passwordPossibilities.add(passwordChars);
                //looks like this: BCDEFGHIJK,ACDEFGHIJK,ABDEFGHIJK,ABCEFGHIJK,ABCDFGHIJK,..
            }
        }
        // if message is not empty, get records and convert each to Hint and put it in hintsToProcess
        LinkedList<String[]> recordsToProcess = new LinkedList<>(message.getLines());

        while (!recordsToProcess.isEmpty()) {
            HintInformation hint = new HintInformation();
            String[] recordToProcess = recordsToProcess.removeFirst();
            hint.setHashedHints(Arrays.copyOfRange(recordToProcess, 5, recordToProcess.length));
            //copies the hints, for example from 1582824a01c4b84...to 4b47ac115f6a91120d...in line 1
            hint.setHashedPassword(recordToProcess[4]);

            hintsToCrack.add(hint);
        }

        // while there are free workers and work, give workers work:
        dispatchFreeWorkers();

        // TODO: Fetch further lines from the Reader
        // also a todo from thorsten, for now the oneliner he provided looks good to me :). might not be enough though
        this.reader.tell(new Reader.ReadMessage(), this.self());
    }

    protected void dispatchFreeWorkers() {
        // I noticed that basically everytime we receive a message, we would like a worker to go work on something
        // todo I am not sure if this approach works 100% of the time? might need improvement

        while (!this.freeWorkers.isEmpty()) {
            // get a free worker
            ActorRef worker = this.freeWorkers.removeFirst();
            // tell the worker to go to work
            if (!hintsToCrack.isEmpty()) {
                worker.tell(new Worker.WorkOnHintMessage(this.passwordPossibilities, hintsToCrack.removeFirst()), this.self());
            } else if (!passwordsToCrack.isEmpty()) {
                worker.tell(new Worker.WorkOnPasswordMessage(passwordsToCrack.removeFirst(), this.passwordLength), this.self());
            }
        }
    }

    protected void terminate() {
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

        dispatchFreeWorkers();
    }

    protected void handle(Terminated message) {
        this.context().unwatch(message.getActor());
        this.workers.remove(message.getActor());
        this.log().info("Unregistered {}", message.getActor());
    }
}
