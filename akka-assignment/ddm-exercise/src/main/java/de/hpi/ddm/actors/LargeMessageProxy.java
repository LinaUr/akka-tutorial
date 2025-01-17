package de.hpi.ddm.actors;

import akka.NotUsed;
import akka.actor.AbstractLoggingActor;
import akka.actor.ActorRef;
import akka.actor.ActorSelection;
import akka.actor.Props;
import akka.stream.SourceRef;
import akka.stream.javadsl.Sink;
import akka.stream.javadsl.Source;
import akka.stream.javadsl.StreamRefs;
import akka.util.ByteString;
import com.twitter.chill.KryoPool;
import de.hpi.ddm.singletons.KryoPoolSingleton;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletionStage;

public class LargeMessageProxy extends AbstractLoggingActor {

	////////////////////////
	// Actor Construction //
	////////////////////////

	public static final String DEFAULT_NAME = "largeMessageProxy";
	private static final int CHUNK_SIZE = 1024; // 1kB;

	public static Props props() {
		return Props.create(LargeMessageProxy.class);
	}

	////////////////////
	// Actor Messages //
	////////////////////

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class LargeMessage<T> implements Serializable {
		private static final long serialVersionUID = 2940665245810221108L;
		private T message;
		private ActorRef receiver;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class BytesMessage<T> implements Serializable {
		private static final long serialVersionUID = 4057807743872319842L;
		// to tell receiver where to look for stream
		private SourceRef<ByteString> sourceRef;
		private ActorRef sender;
		private ActorRef receiver;
	}

	/////////////////
	// Actor State //
	/////////////////

	/////////////////////
	// Actor Lifecycle //
	/////////////////////

	////////////////////
	// Actor Behavior //
	////////////////////

	@Override
	public Receive createReceive() {
		return receiveBuilder()
				.match(LargeMessage.class, this::handle)
				.match(BytesMessage.class, this::handle)
				.matchAny(object -> this.log().info("Received unknown message: \"{}\"", object.toString()))
				.build();
	}

	private void handle(LargeMessage<?> largeMessage) {
//		this.log().info("About to send message: \"{}\"", largeMessage.getMessage().toString());

		// boilerplate by Thorsten that looks good
		Object message = largeMessage.getMessage();
		ActorRef sender = this.sender();
		ActorRef receiver = largeMessage.getReceiver();
		ActorSelection receiverProxy = this.context().actorSelection(receiver.path().child(DEFAULT_NAME));

		// serialize message
		KryoPool kryo = KryoPoolSingleton.get();
		byte[] serializedMessage = kryo.toBytesWithClass(message);

		// chunk message
		List<ByteString> messageChunks = new ArrayList<>();
		for (int start = 0; start < serializedMessage.length; start += CHUNK_SIZE) {
			messageChunks.add(ByteString.fromArray(serializedMessage, start, CHUNK_SIZE));
		}

		// create source of stream
		Source<ByteString, NotUsed> messagePartsSource = Source.from(messageChunks);

		// stream source
		SourceRef<ByteString> sourceRef;
		sourceRef = messagePartsSource.runWith(StreamRefs.sourceRef(), this.context().system());
//		this.log().info("Stream is ready, sending SourceRef to now.");

		// tell receiver to stream source
		receiverProxy.tell(new BytesMessage<>(sourceRef, sender, receiver), this.self());
	}

	private void handle(BytesMessage<?> message) {
		try {
//			this.log().info("Receiver is trying to stream message.");

			// get source from from sourceRef
			Source<ByteString, NotUsed> source = message.getSourceRef().getSource();

			// https://doc.akka.io/docs/akka/current/stream/operators/Sink/seq.html
			// initialize sink with sinkseq to to receive Stream
			CompletionStage<List<ByteString>> result = source.runWith(Sink.seq(), this.context().system());

			// process complete message
			result.thenAccept(list -> receiveCompleteMessage(list, message.getReceiver(), message.getSender()));
		} catch (Exception e) {
			this.log().error("An Error occurred!");
			e.printStackTrace();
		}
	}

	private void receiveCompleteMessage(List<ByteString> receivedByteStrings, ActorRef receiver, ActorRef sender) {

//		this.log().info("Received number of ByteStrings: {}", receivedByteStrings.size());

		// length of bytes is the sum over the lengths of the chunks
		byte[] bytes = new byte[receivedByteStrings.stream().map(msg -> msg.length()).mapToInt(Integer::intValue).sum()];
		// convert List<BysteString> to byte[]
		int position = 0;
		for (ByteString byteString : receivedByteStrings) {
			System.arraycopy(byteString.toArray(), 0, bytes, position, byteString.length());
			position += CHUNK_SIZE;
		}

		// deserialize message
		KryoPool kryo = KryoPoolSingleton.get();
		Object message = kryo.fromBytes(bytes);

//		this.log().info("Received message: {}", message);

		// finally tell receiver about message
		receiver.tell(message, sender);
	}
}