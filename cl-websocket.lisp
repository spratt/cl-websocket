;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;                                                                         ;;;
;;; Copyright (c) 2010, Simon David Pratt <me@simondavidpratt.com>          ;;;
;;;                                                                         ;;;
;;; Permission to use, copy, modify, and/or distribute this software        ;;;
;;; for any purpose with or without fee is hereby granted, provided         ;;;
;;; that the above copyright notice and this permission notice appear       ;;;
;;; in all copies.                                                          ;;;
;;;                                                                         ;;;
;;; THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL           ;;;
;;; WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED           ;;;
;;; WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE        ;;;
;;; AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR                  ;;;
;;; CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM          ;;;
;;; LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,         ;;;
;;; NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN               ;;;
;;; CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.                ;;;
;;;                                                                         ;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;                                                                         ;;;
;;; FILE:    cl-websocket.lisp                                              ;;;
;;;                                                                         ;;;
;;; MODULE:  Common-Lisp-Websocket                                          ;;;
;;;                                                                         ;;;
;;; NOTES:   Implements the WebSocket draft protocol as specified in        ;;;
;;;          draft-ietf-hybi-thewebsocketprotocol-03.                       ;;;
;;;                                                                         ;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(cl:in-package #:cl-user)

(cl:defpackage #:cl-websocket
  (:use #:cl))

(cl:in-package #:cl-websocket)

(ql:quickload "md5")
(ql:quickload "trivial-utf-8")

(defun split-string (string &key (delimiter (string #\Space)) (max -1))
    "Returns a list of substrings of string
divided by the delimiter.  If there are more than max
delimiters in the string, the last substring will be contain
the unsplit string remaining after the maxth delimiter.

Max is -1 by default, which splits the string on all delimiters.
Note: Two consecutive delimiters will be seen as
if there were an empty string between them."
    (let ((pos (search delimiter string)))
      (if (or (= max 0) (eq nil pos))
	  (list string)
	  (cons
	   (subseq string 0 pos)
	   (split-string (subseq string (+ pos (length delimiter)))
			 :delimiter delimiter
			 :max (if (= max -1)
				  -1
				  (- max 1)))))))

(defun parse-header (header)
  "Takes an HTTP header and returns a list of sublists of strings,
where the first string is the fieldname and the second string is
the value of that field."
  (loop for string in (split-string header :delimiter (string #\Newline))
       collect (split-string string :max 1)))

(defun get-field (fields fieldname)
  "Takes the output of parse-header and returns the value of
the given fieldname."
  (dolist (field fields)

    (when (string= fieldname (subseq (car field) 0 (- (length (car field)) 1)))
      (return (cadr field)))))

(defun parse-number (string)
  "Returns the number given by appending the digits in a string
and dividing by the number of spaces in the string."
  (let ((i 1)
	(number 0)
	(spaces 0))
    (loop
       for p from (- (length string) 1) downto 0
       for char = (char string p)
       when (eq char #\Space)
       do
	 (setf spaces (1+ spaces))
       when (digit-char-p char)
       do
	 (setf number (+ number (* i (parse-integer (string char)))))
	 (setf i (* i 10)))
    (/ number spaces)))

(defun number-to-bytes (number)
  "Generates a vector of bytes from a number"
  (let ((array (make-array 4 :element-type '(unsigned-byte 8))))
    (loop
       for i from 0 to 3
       do
       (setf (aref array (- 3 i))
	     (coerce (ldb (byte 8 (* i 8)) number) '(unsigned-byte 8))))
    array))

(defun string-to-bytes (string)
  "Returns a vector of bytes contained in the input string."
  (trivial-utf-8:string-to-utf-8-bytes string))

(defun bytes-to-string (byte-array)
  "Takes a vector of bytes and returns the utf-8 string equivalent."
  (trivial-utf-8:utf-8-bytes-to-string byte-array))

(defun cat-byte-array (a1 a2)
  "Concatenates two arrays of type (unsigned-byte 8)"
  (let ((array (make-array (+ (length a1) (length a2))
			   :element-type '(unsigned-byte 8))))
    ;; The double loop is sort of nasty, but it's better than recursion
    ;; because it only creates one array to return.
    (loop
       for i from 0 to (- (length a1) 1)
       do
	 (setf (aref array i) (aref a1 i)))
    (loop
       for i from 0 to (- (length a2) 1)
       do
	 (setf (aref array (+ i (length a1))) (aref a2 i)))
    array))

(defun handshake-reply (keynumber1 keynumber2 string)
  "Concatenates keynumber1 and keynumber2 as big-endian 32 bit numbers
with the 8-byte string, takes the md5 sum and returns the utf8 string.

See: the handshake protocol of draft-ietf-hybi-thewebsocketprotocol-03"
  (bytes-to-string
   (md5:md5sum-sequence
    (cat-byte-array
     (number-to-bytes keynumber1)
     (cat-byte-array
      (number-to-bytes keynumber2)
      (string-to-bytes string))))))

(defun parse-packet (http-packet)
  "Takes an HTTP packet, and returns a cons where the car is the header of
the packet and the cadr is the body of the packet."
  (split-string http-packet :delimiter #(#\Newline #\Newline) :max 1))

(defun server-response (http-packet)
  "Given an HTTP packet, returns the server response packet."
  (let* ((parsed-packet (parse-packet http-packet))
	 (parsed-header (parse-header (car parsed-packet)))
	 (body (handshake-reply (parse-number (get-field parsed-header
							 "Sec-WebSocket-Key1"))
				(parse-number (get-field parsed-header
							 "Sec-WebSocket-Key2"))
				(cadr parsed-packet))))
    (concatenate 'string
		 "HTTP/1.1 101 WebSocket Protocol Handshake" #(#\Newline)
		 "Upgrade: WebSocket" #(#\Newline)
		 "Connection: Upgrade" #(#\Newline)
		 "Sec-WebSocket-Origin: " (get-field parsed-header "Origin")
		 #(#\Newline)
		 "Sec-WebSocket-Location: ws://" (get-field parsed-header "Host")
		 #(#\Newline)
		 "Sec-WebSocket-Protocol: " (car
					     (split-string
					      (get-field parsed-header
							 "Sec-WebSocket-Protocol")))
		 #(#\Newline) #(#\Newline)
		 body)))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Test Code                                                               ;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(setf *testpacket1*
      "GET /demo HTTP/1.1
Host: example.com
Connection: Upgrade
Sec-WebSocket-Key2: 12998 5 Y3 1  .P00
Sec-WebSocket-Protocol: sample
Upgrade: WebSocket
Sec-WebSocket-Key1: 4 @1  46546xW%0l 1 5
Origin: http://example.com

^n:ds[4U")

;; Handshake response should be: "8jKS'y:G*Co,Wxa-"

(setf *testpacket2*
      "GET /demo HTTP/1.1
Host: example.com
Connection: Upgrade
Sec-WebSocket-Key2: 1_ tx7X d  <  nw  334J702) 7]o}` 0
Sec-WebSocket-Protocol: sample
Upgrade: WebSocket
Sec-WebSocket-Key1: 18x 6]8vM;54 *(5:  {   U1]8  z [  8
Origin: http://example.com

Tm[K T2u")

;; Handshake response should be: "fQJ,fN/4F4!~K~MH"