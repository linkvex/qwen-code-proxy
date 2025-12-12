/**
 * Stream transformer to handle API responses and prevent stuttering
 * by properly buffering and parsing Server-Sent Events with de-duplication.
 */

export function createSSETransformer(): TransformStream<
  Uint8Array,
  Uint8Array
> {
  let buffer = "";
  let lastContent = "";
  let chunkIndex = 0;

  return new TransformStream({
    transform(chunk, controller) {
      if (chunk && chunk.byteLength > 0) {
        chunkIndex++;

        // Decode the chunk to string
        const chunkStr = new TextDecoder().decode(chunk);

        // Add to buffer
        buffer += chunkStr;

        // Split by double newlines which separate SSE events
        const events = buffer.split("\n\n");

        // The last item might be an incomplete event, so keep it in the buffer
        buffer = events.pop() || "";

        // Process all complete events
        for (const event of events) {
          if (event.trim()) {
            // Check if this is a data event containing content
            if (event.startsWith("data: ")) {
              try {
                // Parse the JSON data
                const dataStr = event.substring(6); // Remove "data: " prefix
                const dataObj = JSON.parse(dataStr);

                // Check if this is a chat completion chunk with content
                if (
                  dataObj.choices &&
                  dataObj.choices[0] &&
                  dataObj.choices[0].delta
                ) {
                  const content = dataObj.choices[0].delta.content;

                  // If we have content and it matches the last content, skip it (de-duplication)
                  if (content && content === lastContent) {
                    continue; // Skip this duplicate event
                  }

                  // Update last content if we have new content
                  if (content) {
                    lastContent = content;
                  }
                }
              } catch (e) {
                // If JSON parsing fails, just pass the event through
              }
            }

            // Add back the \n\n separator and enqueue the complete event
            controller.enqueue(new TextEncoder().encode(event + "\n\n"));
          }
        }
      }
    },
    flush(controller) {
      // Process any remaining buffered content
      if (buffer.length > 0) {
        controller.enqueue(new TextEncoder().encode(buffer));
      }

      // Reset content tracking for next request
      lastContent = "";
    },
  });
}
