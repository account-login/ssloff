package ssloff

type SLElement struct {
	Next  *SLElement
	Value interface{}
}

type SList struct {
	Head *SLElement
	Tail *SLElement
}

func (l *SList) Empty() bool {
	return l.Head == nil
}

func (l *SList) PopFront() *SLElement {
	h := l.Head
	l.Head = h.Next
	if l.Head == nil {
		l.Tail = nil
	}
	h.Next = nil
	return h
}

func (l *SList) PushBack(t *SLElement) {
	if l.Head == nil {
		l.Head = t
	} else {
		l.Tail.Next = t
	}
	l.Tail = t
}

func (l *SList) PushFront(t *SLElement) {
	if l.Head == nil {
		l.Tail = t
	} else {
		t.Next = l.Head
	}
	l.Head = t
}
