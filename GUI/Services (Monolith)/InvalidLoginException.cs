using System.Runtime.Serialization;

namespace GUI.ServicesMonolith
{
    [Serializable]
    internal class InvalidLoginException : Exception
    {
        public InvalidLoginException() : base ("Invalid username or password")
        {
        }

        public InvalidLoginException(string message) : base(message)
        {
        }

        public InvalidLoginException(string? message, Exception? innerException) : base(message, innerException)
        {
        }

        protected InvalidLoginException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}