# FAQ

# What Photo-Verify is not:
- An authentication mechanism to prove that the photo has not been modified. That should be handled in-camera. In fact it's the opposite: it allows any modification, but it records the change by resigning the new file. This allows finding the original author of the file and therefore the original image.
- A mechanism to record what has been changed in a photograph. Anything can be done to the photos, we're not here to stop creativity. Just record the new version and the chain is preserved to the original.
- A system to check the origin of a photo by analysing it like Google image search. Only photos that have been processed by the system can be checked. It is however possibel to lookup a match from an unsigned photo if it was otherwise signed by the system in the past (for example to prove that a photo is yours, even if the unsigned original was stolen from you).
- A way to stop people from stealing your photos. We can't stop people from modifying your photos and removing the signature. But the point of this mechanism is that they wouldn't be able to attribute a photo they modified to you. It is also possible to lookup a signature using an original unsigned photo.
- A library of images where you can look up an image and download it. No photos are stored on the server, they're yours only.

# What if someone registers your photos as theirs? 
- We can't stop that. The workflow I'd follow is as follows:
- Every time I plan to publish a photo or send it a photo for publication, sign the original raw file.
- Then when I send it or publish it online, sign the version I'm sending before sending it. That way, it is possible to trace any version of the photo to your original.
