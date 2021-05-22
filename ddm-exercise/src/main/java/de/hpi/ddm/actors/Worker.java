package de.hpi.ddm.actors;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import akka.actor.AbstractLoggingActor;
import akka.actor.ActorRef;
import akka.actor.PoisonPill;
import akka.actor.Props;
import akka.cluster.Cluster;
import akka.cluster.ClusterEvent.CurrentClusterState;
import akka.cluster.ClusterEvent.MemberRemoved;
import akka.cluster.ClusterEvent.MemberUp;
import de.hpi.ddm.structures.BloomFilter;
import de.hpi.ddm.systems.MasterSystem;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import akka.cluster.Member;
import akka.cluster.MemberStatus;

public class Worker extends AbstractLoggingActor {

    ////////////////////////
    // Actor Construction //
    ////////////////////////

    public static final String DEFAULT_NAME = "worker";

    public static Props props() {
        return Props.create(Worker.class);
    }

    public Worker() {
        this.cluster = Cluster.get(this.context().system());
        this.largeMessageProxy = this.context().actorOf(LargeMessageProxy.props(), LargeMessageProxy.DEFAULT_NAME);
    }

    ////////////////////
    // Actor Messages //
    ////////////////////

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class WelcomeMessage implements Serializable {
        private static final long serialVersionUID = 8343040942748609598L;
        private BloomFilter welcomeData;
    }

    // line to process arrives through WorkOnHintmessage
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class WorkOnHintMessage implements Serializable {
        private static final long serialVersionUID = 8777040942748609598L;
        private List<char[]> hintPossibilities;
        private List<Character> possibleChars;
        private Master.HintInformation hint; // we do not need the hashed password it here directly, but when it is part of the message,
        // we can pass it on so we do not have to look it up again later
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class WorkOnPasswordMessage implements Serializable {
        private static final long serialVersionUID = 8777040942123409598L;
        private Master.PasswordData passwordData;
        private int passwordLength;
    }

    /////////////////
    // Actor State //
    /////////////////

    private Member masterSystem;
    private final Cluster cluster;
    private final ActorRef largeMessageProxy;
    private long registrationTime;

    /////////////////////
    // Actor Lifecycle //
    /////////////////////

    @Override
    public void preStart() {
        Reaper.watchWithDefaultReaper(this);

        this.cluster.subscribe(this.self(), MemberUp.class, MemberRemoved.class);
    }

    @Override
    public void postStop() {
        this.cluster.unsubscribe(this.self());
    }

    ////////////////////
    // Actor Behavior //
    ////////////////////

    @Override
    public Receive createReceive() {
        return receiveBuilder()
                .match(CurrentClusterState.class, this::handle)
                .match(MemberUp.class, this::handle)
                .match(MemberRemoved.class, this::handle)
                .match(WelcomeMessage.class, this::handle)
                .match(WorkOnHintMessage.class, this::handle)
                .match(WorkOnPasswordMessage.class, this::handle)
                .matchAny(object -> this.log().info("Received unknown message: \"{}\"", object.toString()))
                .build();
    }

    private void handle(WorkOnHintMessage message) {
        List<String> hashedHints = Arrays.asList(message.getHint().getHashedHints());
        List<char[]> hintPossibilities = message.getHintPossibilities();
        List<Character> possibleChars = message.getPossibleChars(); // A to K ..used for checkup
        ArrayList<Character> charsInPassword = new ArrayList<Character>(message.getPossibleChars()); // A to K

//        this.log().info("hintPossibilities legnth : possibileChars length {} : {}",hintPossibilities.size(), possibleChars.size() );
//        this.log().info("char posiibilities:");
//        hintPossibilities.forEach(charArr -> System.out.println(Arrays.toString(charArr)));

        // We know that hintPossibilities.size() == possibileChars.size()
        // So we iterate over all possible hints and permutate them while checking against the hashed hint along the process.
        // In case we crack a hint, we remove the corresponding character as it won't be in the password then.
        for (int i = 0; i < hintPossibilities.size(); i++){
            System.out.println("checking possible hint " + i);
            List<String> permutations = new ArrayList<>(); // we don't really need that
            char[] possibleHint = hintPossibilities.get(i); // BCDEFGHIJK (missing A), ACDEFGHIJK (missing B), ...
            StringBuilder crackedHint = new StringBuilder();
            // permutate them while checking against the hashed hint along the process.
            heapPermutation(possibleHint, possibleHint.length, possibleHint.length, permutations, hashedHints, crackedHint);
            if (crackedHint.length() != 0) {
                // we cracked a hint
                charsInPassword.remove(possibleChars.get(i));
                System.out.println(charsInPassword);
            }
        }

//        charsInPassword = new ArrayList<Character>(); // testing reasons
//        charsInPassword.add('F'); // testing reasons
//        charsInPassword.add('G'); // testing reasons

        // then: give Master result
        ActorRef master = this.sender();
        master.tell(new Master.HintResultMessage(charsInPassword, message.getHint().getHashedPassword()), this.self());
    }

    private void handle(WorkOnPasswordMessage message) {
        // todo one of the hardest parts i think, finding the permutation of known characters that is the password
        //  while not knowing how often each character appears..
        String hashedPassword = message.getPasswordInformation().getHashedPassword();
        Set<Character> passwordCharacters = message.getPasswordInformation().getPasswordCharacters();
        int passwordLength = message.getPasswordLength();
        LinkedList<String> characterCombinations = new LinkedList<String>();
        for(int i=1; i < passwordLength; i++) {
            String characterCombination = "";
            for(int j = 0; j < i; j++) {
                characterCombination += passwordCharacters.toArray()[0];
            }
            for(int k = i; k<passwordLength; k++) {
                characterCombination += passwordCharacters.toArray()[1];
            }
            System.out.println(characterCombination);
            characterCombinations.add(characterCombination);
        }

        // to show that this is actually executed and the passwordCharacter are calculated nicely:
        System.out.println(passwordCharacters);

        // find permutation
        // check permutation like this: this.hash(permuation).equals(hashedPassword);

        // then send found password back to master
        // ActorRef master = this.sender();
        // master.tell(new Master.PasswordResultMessage(permutation, hashedPassword()), this.self());
    }

    private void handle(CurrentClusterState message) {
        message.getMembers().forEach(member -> {
            if (member.status().equals(MemberStatus.up()))
                this.register(member);
        });
    }

    private void handle(MemberUp message) {
        this.register(message.member());
    }

    private void register(Member member) {
        if ((this.masterSystem == null) && member.hasRole(MasterSystem.MASTER_ROLE)) {
            this.masterSystem = member;

            this.getContext()
                    .actorSelection(member.address() + "/user/" + Master.DEFAULT_NAME)
                    .tell(new Master.RegistrationMessage(), this.self());

            this.registrationTime = System.currentTimeMillis();
        }
    }

    private void handle(MemberRemoved message) {
        if (this.masterSystem.equals(message.member()))
            this.self().tell(PoisonPill.getInstance(), ActorRef.noSender());
    }

    private void handle(WelcomeMessage message) {
        final long transmissionTime = System.currentTimeMillis() - this.registrationTime;
        this.log().info("WelcomeMessage with " + message.getWelcomeData().getSizeInMB() + " MB data received in " + transmissionTime + " ms.");
    }

    private String hash(String characters) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashedBytes = digest.digest(String.valueOf(characters).getBytes("UTF-8"));

            StringBuffer stringBuffer = new StringBuffer();
            for (int i = 0; i < hashedBytes.length; i++) {
                stringBuffer.append(Integer.toString((hashedBytes[i] & 0xff) + 0x100, 16).substring(1));
            }
            return stringBuffer.toString();
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    // Generating all permutations of an array using Heap's Algorithm
    // https://en.wikipedia.org/wiki/Heap's_algorithm
    // https://www.geeksforgeeks.org/heaps-algorithm-for-generating-permutations/
//    private void heapPermutation(char[] a, int size, int n, List<String> l) {
    private void heapPermutation(char[] a, int size, int n, List<String> l, List<String> hashedHints, StringBuilder crackedHint) {

        if (crackedHint.length() != 0)
            return; // hint was cracked then

        // If size is 1, store the obtained permutation
        if (size == 1) {
            l.add(new String(a));
            String permutationHash = hash(new String(a));
            if (hashedHints.contains(permutationHash)) {
                crackedHint.append(new String(a));
                this.log().info("Hint cracked: {}", crackedHint);
            }
        }

        for (int i = 0; i < size; i++) {
            heapPermutation(a, size - 1, n, l, hashedHints, crackedHint);

            // If size is odd, swap first and last element
            if (size % 2 == 1) {
                char temp = a[0];
                a[0] = a[size - 1];
                a[size - 1] = temp;
            }

            // If size is even, swap i-th and last element
            else {
                char temp = a[i];
                a[i] = a[size - 1];
                a[size - 1] = temp;
            }
        }
    }
}