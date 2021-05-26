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

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class WorkOnHintMessage implements Serializable {
        private static final long serialVersionUID = 1522652675066025890L;
        private char[] alphabet;
        private Master.HintData hintData;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class WorkOnPasswordMessage implements Serializable {
        private static final long serialVersionUID = 4591909895490294199L;
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
        char[] alphabet = message.alphabet;
        Master.HintData hintData = message.hintData;
        List<String> hashedHints = Arrays.asList(hintData.hashedHints);
        int indexCharToCheck = hintData.indexCharToCheck;

        char[] charsToPermute = new char[message.alphabet.length - 1];
        new StringBuilder(new String(message.alphabet))
                .deleteCharAt(indexCharToCheck)
                .getChars(0, message.alphabet.length - 1, charsToPermute, 0);

        // permuting the char combination while checking against the hashed hints along the process
        String crackedHint = this.heapPermutation(charsToPermute, charsToPermute.length, hashedHints);
        Character missingChar = crackedHint.isEmpty() ? null : alphabet[indexCharToCheck];
        this.log().info("hint cracked: {}, remove char: {}", crackedHint, missingChar);

        ActorRef master = this.sender();
        this.largeMessageProxy.tell(new LargeMessageProxy.LargeMessage<>(new Master.HintResultMessage(hintData.passwordId, missingChar), master), this.self());
    }

    private void handle(WorkOnPasswordMessage message) {
        Master.PasswordData pwData = message.passwordData;

        // generating all possible strings for password while checking against the hashed password along the process
        String plainPW = crackPassword(pwData.charsInPassword, "", pwData.charsInPassword.size(), message.passwordLength, pwData.hashedPassword);
        if (plainPW.isEmpty()) {
            plainPW = "An error must have been occurred along the process, couldn't crack the password.";
        }

        ActorRef master = this.sender();
        this.largeMessageProxy.tell(new LargeMessageProxy.LargeMessage<>(new Master.PasswordResultMessage(plainPW, pwData), master), this.self());
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
    private String heapPermutation(char[] a, int size, List<String> hashedHints) {

        // If size is 1, store the obtained permutation
        if (size == 1) {
//            this.log().info("permutation: {}", new String(a));
            if (hashedHints.contains(hash(new String(a)))) {
                return new String(a);
            }
        }

        for (int i = 0; i < size; i++) {
            String perm = heapPermutation(a, size - 1, hashedHints);
            if (!perm.isEmpty())
                return perm;

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
        return "";
    }

    // Generating all possible strings of length k given n characters
    // https://www.geeksforgeeks.org/print-all-combinations-of-given-length/
    private String crackPassword(List<Character> set, String combination, int n, int k, String originalHashedPassword)
    {
        // Base case: k is 0,
        // print combination
        if (k == 0)
        {
            String hashedGeneratedPassword = hash(combination);
            if (hashedGeneratedPassword.equals(originalHashedPassword)){
                return combination;
            }
            return "";
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
            String combi = crackPassword(set, newPrefix, n, k - 1, originalHashedPassword);
            if (!combi.isEmpty())
                return combi; // we have cracked the password :D
        }
        return "";
    }
}