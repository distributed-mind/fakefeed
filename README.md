## fakefeed
## **Experimental**

this is is some experimental code for creating a local feed

[#ssb-learning](http://ssb.mikey.nz:8807/channel/ssb-learning)

to start a local feed, just simply run:
- `go run ff.go msg "test message 1"` to create the first message
- and then `go run ff.go msg "test message 2"` to create the second message, and so on
you can then see the messages in the feed directory

to import a blob, run this:
- `go run ff.go blob /path/to/file`

to view imported blobs, run this:
- `go run ff.go blob`

