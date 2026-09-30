// ---- LTI role -> internal role mapping ----
// LTI 1.3 roles are full IMS vocabulary URNs (context roles such as
// .../membership#Instructor, or system roles such as .../system/person#Administrator),
// not free text. Matching them precisely -- instead of a blanket
// /Instructor|ContentDeveloper|Administrator/i regex, which would collapse every one of
// those into a single "instructor" bucket with identical rights -- is what lets
// different LTI roles carry different actual permissions. Two instructor-tier
// roles exist on tutor-service's side: 'course_supervisor' (full rights,
// including the Verification queue) and 'section_instructor' (content/analytics
// access, no verification authority). This is where that split gets decided, not
// left implicit at each call site.
//
// Context roles can also arrive as sub-roles (".../membership/Instructor#TeachingAssistant"
// -- a TA *within* the Instructor role) or, from some platforms, as bare LTI 1.1 short
// names ("Instructor", "TeachingAssistant"). Both are normalized to the same
// "principal#sub" form before matching, so a TA sent as a sub-role isn't mistaken
// for a student.

const CONTEXT_PREFIX = 'http://purl.imsglobal.org/vocab/lis/v2/membership';

// Normalizes one role to { principal, sub } for context roles, or null for anything else.
//   .../membership#Instructor                    -> { principal: 'Instructor', sub: null }
//   .../membership/Instructor#TeachingAssistant  -> { principal: 'Instructor', sub: 'TeachingAssistant' }
//   Instructor (short name)                      -> { principal: 'Instructor', sub: null }
function parseContextRole(role) {
  const r = String(role || '');
  if (r.startsWith(`${CONTEXT_PREFIX}#`)) return { principal: r.slice(CONTEXT_PREFIX.length + 1), sub: null };
  if (r.startsWith(`${CONTEXT_PREFIX}/`)) {
    const [principal, sub] = r.slice(CONTEXT_PREFIX.length + 1).split('#');
    return { principal, sub: sub || null };
  }
  if (/^[A-Za-z]+$/.test(r)) return { principal: r, sub: null }; // LTI 1.1-style short name
  return null;
}

const ADMIN_ROLES = ['system/person#Administrator', 'institution/person#Administrator'];
// Sub-roles of Instructor that assist rather than own the course.
const ASSISTING_INSTRUCTOR_SUBROLES = ['TeachingAssistant', 'Grader'];

function mapLtiRolesToInternalRole(ltiRoles) {
  const roles = ltiRoles || [];
  const context = roles.map(parseContextRole).filter(Boolean);
  const has = (predicate) => context.some(predicate);

  const isAdmin = roles.some((r) => ADMIN_ROLES.some((suffix) => String(r).endsWith(suffix)));
  const isFullInstructor = has((c) => (c.principal === 'Instructor' || c.principal === 'Administrator')
    && !ASSISTING_INSTRUCTOR_SUBROLES.includes(c.sub));
  if (isAdmin || isFullInstructor) return 'course_supervisor';

  const isAssistant = has((c) => c.principal === 'ContentDeveloper' || c.principal === 'TeachingAssistant'
    || (c.principal === 'Instructor' && ASSISTING_INSTRUCTOR_SUBROLES.includes(c.sub)));
  if (isAssistant) return 'section_instructor';

  // Mentors/observers (parents, advisors) who aren't also learners have no
  // Rennix view yet, and must never be treated -- or billed -- as students.
  const isLearner = has((c) => c.principal === 'Learner');
  const isMentor = has((c) => c.principal === 'Mentor');
  if (isMentor && !isLearner) return 'observer';

  return 'student';
}

const INSTRUCTOR_ROLES = ['course_supervisor', 'section_instructor'];
function isInstructorRole(internalRole) {
  return INSTRUCTOR_ROLES.includes(internalRole);
}

module.exports = { mapLtiRolesToInternalRole, isInstructorRole, parseContextRole };
