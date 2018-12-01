'''
Created on 03 gen 2016

@author: Matteo
'''

class Event(list):
    """Event subscription.

    A list of callable objects. Calling an instance of this will cause a
    call to each item in the list in ascending order by index.

    Example Usage:
    >>> def f(x):
    ...     print 'f(%s)' % x
    >>> def g(x):
    ...     print 'g(%s)' % x
    >>> e = Event()
    >>> e()
    >>> e.append(f)
    >>> e(123)
    f(123)
    >>> e.remove(f)
    >>> e()
    >>> e += (f, g)
    >>> e(10)
    f(10)
    g(10)
    >>> del e[0]
    >>> e(2)
    g(2)

    """
    
    def append(self, call, **kwargs):
        kwargs['__c'] = call
        return list.append(self, kwargs)
    def __call__(self, *args, **kwargs):
        for f in self:
            kwargs.update(f)
            f['__c'](*args, **kwargs)

    def __repr__(self):
        return "Event(%s)" % list.__repr__(self)

class EventManager(object):
    '''
    classdocs
    '''
    
    instance = None

    def __init__(self):
        if EventManager.instance is None:
            self.events = {}
            EventManager.instance = self
    
    @staticmethod
    def on(evn,mtd,**kwargs):
        if EventManager.instance is None:
            EventManager()
        if evn not in EventManager.instance.events:
            EventManager.instance.events[evn] = Event()
        
        EventManager.instance.events[evn].append(mtd,**kwargs)
    
    @staticmethod
    def fire(eventname,*args, **kwargs):
        if (not (EventManager.instance is None)) and eventname in EventManager.instance.events:
            EventManager.instance.events[eventname](*args, **kwargs)