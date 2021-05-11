package de.hpi.ddm.actors;

import java.io.Serializable;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletionStage;

import akka.NotUsed;
import akka.actor.AbstractLoggingActor;
import akka.actor.ActorRef;
import akka.actor.ActorSelection;
import akka.actor.Props;
import akka.stream.SourceRef;
import akka.stream.javadsl.Sink;
import akka.stream.javadsl.Source;
import akka.stream.javadsl.StreamRefs;
import com.twitter.chill.KryoPool;
import de.hpi.ddm.singletons.KryoPoolSingleton;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

public class LargeMessageProxy extends AbstractLoggingActor {

	////////////////////////
	// Actor Construction //
	////////////////////////

	public static final String DEFAULT_NAME = "largeMessageProxy";
	
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
		private SourceRef<Byte[]> sourceRef;
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
		// boilerplate by Thorsten that looks good
		Object message = largeMessage.getMessage();
		ActorRef sender = this.sender();
		ActorRef receiver = largeMessage.getReceiver();
		ActorSelection receiverProxy = this.context().actorSelection(receiver.path().child(DEFAULT_NAME));

		// serialize message
		KryoPool kryo = KryoPoolSingleton.get();
		byte[] serializedMessage = kryo.toBytesWithClass(message);

		// convert from byte[] to Byte[]
		Byte[] serializedByteMessage = new Byte[serializedMessage.length];
		int i = 0;
		for(byte b: serializedMessage)
			serializedByteMessage[i++] = b; // autoboxing

		System.out.println("serialized and in Byte[]");

		Byte[][] serializedMessageToSend = new Byte[(serializedMessage.length + 1024 - 1) / 1024][33];
		int rest = serializedMessage.length % 1024;
		int j = 0;
		for (int chunk = 0; chunk < serializedMessageToSend.length -1; chunk++) {
			for (int byteindex = 0; byteindex < 1024; byteindex++) {
				serializedMessageToSend[chunk][byteindex] = serializedMessage[j++];
			}
		}
		for (i = 0; j < serializedMessage.length; j++) {
			serializedMessageToSend[serializedMessageToSend.length -1][i++] = serializedMessage[j++];
		}

		// make iterable for source
		List<Byte[]> list = Arrays.asList(serializedMessageToSend);

		// put into source
		Source<Byte[], NotUsed> messagePartsSource = Source.from(list);

		// stream source
		SourceRef<Byte[]> sourceRef;
		sourceRef = messagePartsSource.runWith(StreamRefs.sourceRef(), this.context().system());
		System.out.println("Stream ready");

		// tell receiver to stream source
		receiverProxy.tell(new BytesMessage<>(sourceRef, sender, receiver), this.self());
	}

	private void handle(BytesMessage message) {
		try {
			System.out.println("will try to stream");

			// get source from from sourceRef
			Source<Byte, NotUsed> source = message.getSourceRef().getSource();

			// https://doc.akka.io/docs/akka/current/stream/operators/Sink/seq.html
			// initialize sink with sinkseq to to receive Stream
			CompletionStage<List<Byte>> result = source.runWith(Sink.seq(), this.context().system());

			// process complete message
			result.thenAccept(list ->
					receiveCompleteMessage(list, message.getReceiver(), message.getSender()));
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("throwing an error!");
		}
	}

	private void receiveCompleteMessage(List<Byte> receivedMessage, ActorRef receiver, ActorRef sender) {

		System.out.println(receivedMessage);

		// back from Byte[] to byte []
		byte[] bytes = new byte[receivedMessage.toArray().length];
		int i = 0;
		for (Byte b : receivedMessage)
			bytes[i++] = Byte.valueOf(b);

		// deserialize message
		KryoPool kryo = KryoPoolSingleton.get();
		// TODO: serialize/deserialize without class because class exists in both actors
		Object message = kryo.fromBytes(bytes);
		System.out.println("here is your message:");
		System.out.println(message);

		// finally tell receiver about message
		receiver.tell(message, sender);
	}
}
