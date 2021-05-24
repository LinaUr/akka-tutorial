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
        private Master.PasswordData passwordData; // we do not need the hashed password it here directly, but when it is part of the message,
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
        Master.PasswordData pwData = message.getPasswordData();
        List<String> hashedHints = Arrays.asList(pwData.getHashedHints());
        List<char[]> hintPossibilities = message.getHintPossibilities();
        List<Character> possibleChars = message.getPossibleChars(); // A to K ..used for checkup
        ArrayList<Character> remainingChars = new ArrayList<>(message.getPossibleChars()); // A to K

//        this.log().info("hintPossibilities legnth : possibileChars length {} : {}",hintPossibilities.size(), possibleChars.size() );

        // We know that hintPossibilities.size() == possibileChars.size()
        // So we iterate over all possible hints and permutate them while checking against the hashed hint along the process.
        // In case we crack a hint, we remove the corresponding character as it won't be in the password then.
        for (int i = 0; i < hintPossibilities.size(); i++){
            List<String> permutations = new ArrayList<>(); // we don't really need that
            char[] possibleHint = hintPossibilities.get(i); // BCDEFGHIJK (missing A), ACDEFGHIJK (missing B), ...
            StringBuilder crackedHint = new StringBuilder();
            // permutate them while checking against the hashed hint along the process.
            this.heapPermutation(possibleHint, possibleHint.length, possibleHint.length, permutations, hashedHints, crackedHint);
            if (crackedHint.length() != 0) {
                // yay, we cracked a hint :D
                remainingChars.remove(possibleChars.get(i));
            }
            this.log().info("hint cracked: {}, remaining letters: {}", crackedHint, remainingChars);
        }

//        charsInPassword = new ArrayList<Character>(); // testing reasons
//        charsInPassword.add('F'); // testing reasons
//        charsInPassword.add('G'); // testing reasons

        pwData.setCharsInPassword(remainingChars);
        pwData.setHashedHints(null); // to reduce message content //TODO: is that okay?

        // then: give Master result
        ActorRef master = this.sender();
        master.tell(new Master.HintResultMessage(pwData), this.self());
    }

    private void handle(WorkOnPasswordMessage message) {
        Master.PasswordData pwData = message.getPasswordData();
        String hashedPassword = pwData.getHashedPassword();
        int passwordLength = message.getPasswordLength();

        StringBuilder crackedPassword = new StringBuilder (); // use StringBuilder to ensure pass by reference

        // Generating all possible strings for password while checking against the hashed password along the process
        CrackPassword(pwData.getCharsInPassword(), "", pwData.getCharsInPassword().size(), passwordLength, hashedPassword, crackedPassword);
        this.log().info("cracked password: {}", crackedPassword);

        // send found password back to master
        ActorRef master = this.sender();
        master.tell(new Master.PasswordResultMessage(crackedPassword.toString(), pwData), this.self());
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

    // Generating all possible strings of length k given n characters
    // https://www.geeksforgeeks.org/print-all-combinations-of-given-length/
    void CrackPassword(List<Character> set, String combination, int n, int k, String originalHashedPassword, StringBuilder crackedPassword)
    {
        if (crackedPassword.length() != 0)
            return; // password was already found then :D

        // Base case: k is 0,
        // print combination
        if (k == 0)
        {
//            System.out.println("generated combination: " + combination);
            String hashedGeneratedPassword = hash(combination);
            if (hashedGeneratedPassword.equals(originalHashedPassword)){
                crackedPassword.append(combination);
                this.log().info("Found password " + crackedPassword);
            }
            return;
        }

        // One by one add all characters
        // from set and recursively
        // call for k equals to k-1
        for (int i = 0; i < n; ++i)
        {

            // Next character of input added
            String newPrefix = combination + set.get(i);

            // k is decreased, because
            // we have added a new character
            CrackPassword(set, newPrefix,
                    n, k - 1, originalHashedPassword, crackedPassword);
        }
    }
}