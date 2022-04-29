#! /usr/bin/python3.8

from sys import argv, stderr

MAX_TIC_INDEX = 1000
START_POINT = 5000
END_POINT = 9000
WINDOW_SIZE = 500
FR_THRESHOLD = 150
NHITS_THRESHOLD = 5 
AUTOCHOOSE_THRESHOLD=8

def remove_header(trace):
    for i in range(len(trace)):
        if trace[i].lstrip()[0] != '#':
            return trace[i:]
    return ""


def sanitize_trace(trace):
    t = remove_header(trace)# [1:]
    return t

"""
The confidence depend on the case: if we get few hits, we may conclude false. 
The "few" interval is rather small ([0,5] for instance), but our confidence would
increase faster if we observe "lots" of hits.
Hence, the confidence when observing values below the median is defined by a 
very simple linear function (confidence increase proportionally to the distance 
to the median).
When observing values above, the confidence increase faster, hence we use an 
power law function.
Values at the threshold may be one or the other, and have a low confidence.
"""
def get_confidence(x, ref=NHITS_THRESHOLD):
    if x == ref:
        return round(0, 2)
    # zero is a bit tricky, it may be a measurement error, so we have low confidence
    if x == 0:
        return round(0.33, 2)
    if x < ref:
        return round((ref-x)/ref, 2)
    if x > ref:
        return round(1 - 2**(ref-x), 2)

def weighted_average(distribution, weights):
    numerator = sum([distribution[i]*weights[i] for i in range(len(distribution))])
    denominator = sum(weights)
    return round(numerator/denominator,2)


nhit_list = []
confidence_list = []
for filename in argv[1:]:
    with open(filename) as fp:
        data = sanitize_trace(fp.readlines())
    if len(data) < MAX_TIC_INDEX:
        print(f"skipping {filename}", file=stderr)
        continue
    tic = 0
    # look for the last tic in the beginning of the trace
    for i in range(MAX_TIC_INDEX, 0, -1):
        try:
            x = int(data[i].split(' ')[0])
        except Exception:
            print(f"error on {filename}: ", file=stderr)
        if 10 < x < FR_THRESHOLD:
            tic = i
            break

    # look for the first detection of the second F+R
    for i in range(START_POINT, END_POINT):
        if len(data) <= i:
            break
        try:
            x = int(data[i].split(' ')[1])
        except:
            # Sometimes the measurement is stopped before writing the last value, we skip those
            continue 
        if 10 < x < FR_THRESHOLD:
            t = i - tic
            n_hit = 0
            for j in range(i, i+WINDOW_SIZE):
                if len(data) == j:
                    break
                try:
                    if 10 < int(data[j].split(' ')[1]) < FR_THRESHOLD:
                        n_hit +=1
                except:
                    continue
            nhit_list.append(n_hit)
            confidence_list.append(get_confidence(n_hit))
            break

(macA,macB,_) = argv[1].split('/')[-1].split(':')
avg_hits = weighted_average(nhit_list, confidence_list)

# A very high value allows us to conclude with very high confidence
if max(nhit_list) > AUTOCHOOSE_THRESHOLD:
    print(f"{macA}:{macB}:0:{avg_hits:.2f}:1:{nhit_list}", end=" ")
# If we have enough measurements, the confidence factor becomes irrelevant
elif len(nhit_list) > 2:
    print(f"{macA}:{macB}:{1 if avg_hits < NHITS_THRESHOLD else 0}:{avg_hits:.2f}:1:{nhit_list}", end=" ")
else:
    conf = get_confidence(avg_hits)
    print(f"{macA}:{macB}:{1 if avg_hits < NHITS_THRESHOLD else 0}:{avg_hits:.2f}:{conf:.2f}:{nhit_list}", end=" ")
