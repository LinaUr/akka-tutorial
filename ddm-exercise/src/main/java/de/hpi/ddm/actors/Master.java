package de.hpi.ddm.actors;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import akka.actor.AbstractLoggingActor;
import akka.actor.ActorRef;
import akka.actor.PoisonPill;
import akka.actor.Props;
import akka.actor.Terminated;
import de.hpi.ddm.structures.BloomFilter;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import scala.Int;

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
		this.freeWorkers = new ArrayList<>();
		this.largeMessageProxy = this.context().actorOf(LargeMessageProxy.props(), LargeMessageProxy.DEFAULT_NAME);
		this.welcomeData = welcomeData;
		this.linesToProcess = new ArrayList<>();
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
	
	@Data @NoArgsConstructor @AllArgsConstructor
	public static class BatchMessage implements Serializable {
		private static final long serialVersionUID = 8343040942748609598L;
		private List<String[]> lines;
	}

	@Data
	public static class RegistrationMessage implements Serializable {
		private static final long serialVersionUID = 3303081601659723997L;
	}
// new class for receiving the result from the worker
	@Data @NoArgsConstructor @AllArgsConstructor
	public static class HintResultMessage implements Serializable {
		private static final long serialVersionUID = 393040942748609598L;
		private List<Integer> result;
	}
	/////////////////
	// Actor State //
	/////////////////

	private final ActorRef reader;
	private final ActorRef collector;
	private final List<ActorRef> workers;
	private final ActorRef largeMessageProxy;
	private final BloomFilter welcomeData;

	// 2 queues: one for lines in the csv to process, one of workers to give these lines to:
	private final List<ActorRef> freeWorkers;
	private final List<String[]> linesToProcess;

	private Boolean initialized; // false until first message from reader received to set the following:
	private char[] password; // the "char universe" stays the same
	private int lengthOfPassword; // also stays the same
	private List<char[]> passwordPossibilities;

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
				// TODO: Add further messages here to share work between Master and Worker actors
				.matchAny(object -> this.log().info("Received unknown message: \"{}\"", object.toString()))
				.build();
	}

	protected void handle(StartMessage message) {
		this.startTime = System.currentTimeMillis();
		
		this.reader.tell(new Reader.ReadMessage(), this.self());
	}

	protected void handle(HintResultMessage message) {
		List<Integer> result = message.getResult();
		// TODO: Send (partial) results to the Collector
		// new Todo: parse String not String[] / have actual result
		this.collector.tell(new Collector.CollectMessage("result"), this.self());
		ActorRef worker = this.sender();
		this.freeWorkers.add(worker);
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

		// if first message, set what stays the same:
		if(this.initialized == false) {
			this.initialized = true;
			this.password = message.getLines().get(0)[2].toCharArray(); //ABCDEFGHIJK
			this.lengthOfPassword = Integer.parseInt(message.getLines().get(0)[3]); // 10
			// once, generate a list of strings, each with the password chars minus one
			// this is useful to let different workers work on solving different hints
			for(int i=0; i<this.password.length; i++) {
				char charToLeave = this.password[i];
				char passwordChars[] = new char[this.password.length-1];
				int j = 0;
				for(int k=0; k<this.password.length; k++) {
					char charToAdd = this.password[k];
					if(charToLeave == charToAdd) {
						continue;
					}
					passwordChars[j++] = charToAdd;
				}
				this.passwordPossibilities.add(passwordChars);
			}
			/*for(char[] pp : passwordPossibilities) { // BCDEFGHIJK,ACDEFGHIJK,ABDEFGHIJK,ABCEFGHIJK,ABCDFGHIJK,..
				System.out.print(pp);
				System.out.print(",");
			}*/
		}
		// if message is not empty, add the lines to our linesToProcess:
		this.linesToProcess.addAll(message.getLines());

		// while there are free workers and work, give workers work:

		while (!this.freeWorkers.isEmpty() && !this.linesToProcess.isEmpty()) {
			// get a free worker
			ActorRef worker = this.freeWorkers.remove(0);
			// get the work for the free worker
			String[] lineToProcess = this.linesToProcess.remove(0);
			String[] hashedHints = Arrays.copyOfRange(lineToProcess, 5, lineToProcess.length);
			//copies the hints, for example from 1582824a01c4b84...to 4b47ac115f6a91120d...in line 1

			worker.tell(new Worker.WorkOnHintMessage(this.passwordPossibilities, hashedHints), this.self());
		}

		// TODO: Fetch further lines from the Reader
		// good :)
		this.reader.tell(new Reader.ReadMessage(), this.self());
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
		
		// this.largeMessageProxy.tell(new LargeMessageProxy.LargeMessage<>(new Worker.WelcomeMessage(this.welcomeData), this.sender()), this.self());
		// what do we need this largeMessageProxy for here?
		// TODO: Assign some work to registering workers. Note that the processing of the global task might have already started.
		// Done by adding new worker to free workers.
	}
	
	protected void handle(Terminated message) {
		this.context().unwatch(message.getActor());
		this.workers.remove(message.getActor());
		this.log().info("Unregistered {}", message.getActor());
	}
}
